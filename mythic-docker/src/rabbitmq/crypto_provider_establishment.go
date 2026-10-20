package rabbitmq

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
)

type cryptoProviderExchange struct {
	BindingID        string         `db:"binding_id"`
	RouteUUID        string         `db:"route_uuid"`
	InputDigest      string         `db:"input_digest"`
	RequestID        string         `db:"request_id"`
	NextUUID         string         `db:"next_uuid"`
	SessionBindingID sql.NullString `db:"session_binding_id"`
	Response         []byte         `db:"response"`
}

// Fixed stripes serialize duplicate work in one backend without an unbounded
// lock map. Database claims and provider request IDs also protect other replicas.
var cryptoExchangeLocks [64]sync.Mutex

// This namespace belongs to Mythic's internal RPC correlation scheme. Neither
// identifier is sent as a new cryptographic record or interpreted by a provider.
var cryptoExchangeNamespace = uuid.MustParse("ca915cd0-31ef-57bd-bf9e-5b84f40883c5")

func cryptoPacketDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func cryptoProviderExchangeForRequest(bindingID, route string, body []byte) (cryptoProviderExchange, error) {
	var exchange cryptoProviderExchange
	digest := cryptoPacketDigest(body)
	err := database.DB.Get(&exchange, `SELECT binding_id,route_uuid,input_digest,request_id,next_uuid,session_binding_id,response
		FROM crypto_provider_exchange WHERE binding_id=$1 AND route_uuid=$2 AND input_digest=$3`, bindingID, route, digest)
	if err == nil {
		return exchange, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return exchange, err
	}
	requestID := uuid.NewSHA1(cryptoExchangeNamespace, []byte("request\x00"+bindingID+"\x00"+route+"\x00"+digest))
	nextID := uuid.NewSHA1(cryptoExchangeNamespace, []byte("next-route\x00"+requestID.String()))
	return cryptoProviderExchange{BindingID: bindingID, RouteUUID: route, InputDigest: digest, RequestID: requestID.String(), NextUUID: nextID.String()}, nil
}

func providerFrame(route string, body []byte, size int) ([]byte, error) {
	if id, err := uuid.Parse(route); err != nil || id.String() != route {
		return nil, errors.New("invalid provider response route")
	}
	prefix, err := GetUUIDBytes(route, size)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(append(prefix, body...))), nil
}

func processCryptoProviderEstablishment(info *cachedUUIDInfo, body []byte, uuidSize int, remoteIP string, auth RabbitMQAuthContext) ([]byte, error) {
	if len(body) == 0 || len(body) > provider.MaxMessageBytes {
		return nil, errors.New("invalid provider establishment message size")
	}
	if info.PayloadTypeMessageUUIDLength != uuidSize {
		return nil, errors.New("crypto provider UUID framing mismatch")
	}
	if auth.OperationID != info.OperationID {
		return nil, errors.New("crypto provider operation mismatch")
	}
	if info.CryptoProvider == nil || info.CryptoProviderBindingID == "" || !info.callbackAllowedFromPayload() {
		return nil, errors.New("crypto provider establishment is not allowed")
	}
	if info.UUIDType != UUIDTYPEPAYLOAD && info.UUIDType != UUIDTYPESTAGING {
		return nil, errors.New("invalid crypto establishment route")
	}
	if info.UUIDType == UUIDTYPEPAYLOAD {
		stripe := sha256.Sum256([]byte(info.CryptoProviderBindingID + info.UUID + cryptoPacketDigest(body)))
		lock := &cryptoExchangeLocks[int(stripe[0])%len(cryptoExchangeLocks)]
		lock.Lock()
		defer lock.Unlock()
	}
	exchange, err := cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, body)
	if err != nil {
		return nil, err
	}
	if len(exchange.Response) > 0 {
		return exchange.Response, nil
	}
	if info.UUIDType == UUIDTYPEPAYLOAD {
		if err := validateCryptoProviderMessageSize(info.CryptoProvider, body); err != nil {
			return nil, err
		}
		request, err := requestForBinding(info.CryptoProvider, provider.BeginSession, body, exchange.RequestID, auth)
		if err != nil {
			return nil, err
		}
		request.PayloadUUID = info.PayloadUUID
		request.NextUUID = exchange.NextUUID
		response, err := invokeCryptoProvider(info.CryptoProvider.ProviderName, request)
		if err != nil {
			return nil, err
		}
		encoded, err := providerFrame(info.UUID, response.Message, uuidSize)
		if err != nil {
			return nil, err
		}
		providerJSON := response.ProviderJSON
		if len(providerJSON) == 0 {
			providerJSON = json.RawMessage(`{}`)
		}
		tx, err := database.DB.Beginx()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		// No exchange row is allocated until the provider authenticates a valid
		// registration and returns a complete session result.
		_, err = tx.Exec(`INSERT INTO crypto_provider_exchange(binding_id,route_uuid,input_digest,request_id,next_uuid)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(binding_id,route_uuid,input_digest) DO NOTHING`,
			exchange.BindingID, exchange.RouteUUID, exchange.InputDigest, exchange.RequestID, exchange.NextUUID)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`INSERT INTO crypto_provider_binding(id,profile_id,provider_id,operation_id,scheme,profile_ref,session_ref,namespace,state_id,provider_json)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO NOTHING`, exchange.NextUUID, info.CryptoProviderBindingID, info.CryptoProvider.ProviderID, info.OperationID, info.CryptoProvider.Scheme, info.CryptoProvider.ProfileRef, response.SessionRef, response.Namespace, response.StateID, []byte(providerJSON))
		if err != nil {
			return nil, err
		}
		// A retry cannot silently replace a previously established opaque session.
		var matches bool
		err = tx.Get(&matches, `SELECT provider_id=$2 AND operation_id=$3 AND session_ref=$4 AND namespace=$5 AND profile_id=$6
			AND state_id=$7 AND scheme=$8 AND profile_ref=$9 FROM crypto_provider_binding WHERE id=$1`,
			exchange.NextUUID, info.CryptoProvider.ProviderID, info.OperationID, response.SessionRef, response.Namespace,
			info.CryptoProviderBindingID, response.StateID, info.CryptoProvider.Scheme, info.CryptoProvider.ProfileRef)
		if err != nil {
			return nil, err
		}
		if !matches {
			return nil, errors.New("conflicting crypto session result")
		}
		_, err = tx.Exec(`INSERT INTO staginginfo(session_id,crypto_type,payload_id,staging_uuid,crypto_provider_binding_id)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(staging_uuid) DO NOTHING`, exchange.RequestID, info.CryptoType, info.PayloadID, exchange.NextUUID, exchange.NextUUID)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`UPDATE crypto_provider_exchange SET response=$2,session_binding_id=$3 WHERE request_id=$1`, exchange.RequestID, encoded, exchange.NextUUID)
		if err != nil {
			return nil, err
		}
		if err = tx.Commit(); err != nil {
			return nil, err
		}
		return encoded, nil
	}
	if info.UUIDType != UUIDTYPESTAGING {
		return nil, errors.New("invalid crypto establishment route")
	}
	// Check-in carries the same delegates, responses, edges and proxy data as
	// other actions. Use common dispatch and its durable ownership/reply path.
	result := processCryptoProviderCallback(&AgentMessageRawInput{
		C2Profile: info.C2ProfileName, RemoteIP: remoteIP, AuthContext: auth,
	}, info, body, uuidSize, auth)
	if result.Err != nil {
		return nil, result.Err
	}
	removeCachedEntry(info)
	return result.Message, nil
}

// Preserve the exact serializer/translator output before sealing. Reconstructing
// a semantically identical map after a crash may change JSON member order or
// translator output and would conflict with the original seal request ID.
func sealCryptoProviderExchange(info *cachedUUIDInfo, requestID string, auth RabbitMQAuthContext) ([]byte, error) {
	var saved struct {
		DispatchResponse []byte `db:"dispatch_response"`
		SealInput        []byte `db:"seal_input"`
		Response         []byte `db:"response"`
	}
	err := database.DB.Get(&saved, `SELECT dispatch_response,seal_input,response FROM crypto_provider_exchange
		WHERE request_id=$1 AND binding_id=$2 AND route_uuid=$3`, requestID, info.CryptoProviderBindingID, info.UUID)
	if err != nil {
		return nil, err
	}
	if len(saved.Response) > 0 {
		return saved.Response, nil
	}
	plaintext := saved.SealInput
	if plaintext == nil {
		if len(saved.DispatchResponse) == 0 {
			return nil, errors.New("crypto callback dispatch outcome is unresolved; reestablishment is required")
		}
		// Decode numbers losslessly so a recovered response has the same JSON
		// values even when application IDs exceed float64's integer precision.
		decoder := json.NewDecoder(bytes.NewReader(saved.DispatchResponse))
		decoder.UseNumber()
		var response map[string]interface{}
		if err := decoder.Decode(&response); err != nil {
			return nil, err
		}
		if info.TranslationContainerName == "" {
			plaintext, err = marshalMessageForAgentFormat(info, response)
		} else {
			var converted *TrMythicC2ToCustomMessageFormatMessageResponse
			converted, err = translateCryptoProviderResponse(TrMythicC2ToCustomMessageFormatMessage{
				TranslationContainerName: info.TranslationContainerName,
				C2Name:                   info.C2ProfileName, Message: response, UUID: info.UUID,
				MythicEncrypts: true, CryptoKeys: info.getAllKeys(),
			}, auth)
			if err == nil {
				if converted == nil || !converted.Success || len(converted.Message) == 0 {
					return nil, errors.New("provider response translation failed")
				}
				plaintext = converted.Message
			}
		}
		if err != nil {
			return nil, err
		}
		if len(plaintext) == 0 || len(plaintext) > provider.MaxMessageBytes {
			return nil, errors.New("invalid provider response size")
		}
		err = database.DB.Get(&plaintext, `UPDATE crypto_provider_exchange SET seal_input=COALESCE(seal_input,$4),dispatch_response=NULL
			WHERE request_id=$1 AND binding_id=$2 AND route_uuid=$3 AND response IS NULL RETURNING seal_input`,
			requestID, info.CryptoProviderBindingID, info.UUID, plaintext)
		if errors.Is(err, sql.ErrNoRows) {
			// Another retry may have finished while this translator was running.
			// Never recreate plaintext or seal new bytes for a completed request.
			var completed []byte
			if err := database.DB.Get(&completed, `SELECT response FROM crypto_provider_exchange
				WHERE request_id=$1 AND binding_id=$2 AND route_uuid=$3`, requestID, info.CryptoProviderBindingID, info.UUID); err != nil {
				return nil, err
			}
			if len(completed) == 0 {
				return nil, errors.New("crypto callback response is unavailable")
			}
			return completed, nil
		}
		if err != nil {
			return nil, err
		}
	}
	protected, err := info.IterateAndActWithAuthContext(&plaintext, "encrypt", auth)
	if err != nil {
		return nil, err
	}
	return providerFrame(info.UUID, *protected, info.PayloadTypeMessageUUIDLength)
}

// Keep the test seam local to provider responses; ordinary translation RPCs
// continue to use the existing shared transport implementation.
var translateCryptoProviderResponse = RabbitMQConnection.SendTrRPCMythicC2ToCustomMessage

// Build a request-local view; never copy a mutex or mutate shared cached state
// with a request ID that another incoming request could overwrite.
func providerRequestCache(info *cachedUUIDInfo, requestID string) *cachedUUIDInfo {
	info.stateMutex.RLock()
	defer info.stateMutex.RUnlock()
	return &cachedUUIDInfo{UUID: info.UUID, UUIDType: info.UUIDType, PayloadUUID: info.PayloadUUID, PayloadID: info.PayloadID, PayloadTypeID: info.PayloadTypeID, PayloadTypeName: info.PayloadTypeName, PayloadTypeMessageFormat: info.PayloadTypeMessageFormat, PayloadTypeMessageUUIDLength: info.PayloadTypeMessageUUIDLength, C2ProfileID: info.C2ProfileID, C2ProfileName: info.C2ProfileName, TranslationContainerID: info.TranslationContainerID, TranslationContainerName: info.TranslationContainerName, MythicEncrypts: true, OperationID: info.OperationID, CryptoType: info.CryptoType, CryptoProviderBindingID: info.CryptoProviderBindingID, CryptoProvider: info.CryptoProvider, CryptoProviderRequestID: requestID, CallbackAllowedFromPayload: info.CallbackAllowedFromPayload, CallbackID: info.CallbackID, CallbackDisplayID: info.CallbackDisplayID, Active: info.Active, TriggerOnCheckinAfterTime: info.TriggerOnCheckinAfterTime, EdgeId: info.EdgeId, LastCheckinTime: info.LastCheckinTime, IsP2P: info.IsP2P}
}

// A staging row may already have been consumed while its seal/reply was lost.
// Recover only an exact recorded packet and never dispatch a new staged action.
func cachedCryptoProviderExchange(route string, body []byte, c2 string, auth RabbitMQAuthContext, uuidSize int, remoteIP string) ([]byte, bool, error) {
	if database.DB == nil {
		return nil, false, nil
	}
	var exchange cryptoProviderExchange
	err := database.DB.Get(&exchange, `SELECT e.binding_id,e.route_uuid,e.input_digest,e.request_id,e.next_uuid,e.session_binding_id,e.response
		FROM crypto_provider_exchange e WHERE route_uuid=$1 AND input_digest=$2 ORDER BY request_id LIMIT 1`, route, cryptoPacketDigest(body))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var owner struct {
		OperationID int    `db:"operation_id"`
		SessionRef  string `db:"session_ref"`
	}
	err = database.DB.Get(&owner, `SELECT operation_id,session_ref FROM crypto_provider_binding WHERE id=$1`, exchange.BindingID)
	if err != nil {
		return nil, true, err
	}
	if auth.OperationID != 0 && auth.OperationID != owner.OperationID {
		return nil, true, errors.New("crypto exchange operation mismatch")
	}
	var c2ProfileID int
	if err := database.DB.Get(&c2ProfileID, `SELECT id FROM c2profile WHERE name=$1`, c2); err != nil {
		return nil, true, errors.New("crypto exchange C2 profile is unavailable")
	}
	lookupRoute := route
	if owner.SessionRef != "" {
		// A consumed staging alias is recoverable only through the callback that
		// actually claimed this session. Existing payload aliases still undergo
		// payload authorization rather than inheriting a callback's permissions.
		err = database.DB.Get(&lookupRoute, `SELECT agent_callback_id FROM callback WHERE crypto_provider_binding_id=$1 AND operation_id=$2`, exchange.BindingID, owner.OperationID)
		if errors.Is(err, sql.ErrNoRows) {
			lookupRoute = route
		} else if err != nil {
			return nil, true, err
		}
	}
	info, err := LookupEncryptionData(c2, lookupRoute, false)
	if err != nil {
		return nil, true, err
	}
	if info.CryptoProviderBindingID != exchange.BindingID || info.OperationID != owner.OperationID || !info.callbackAllowedFromPayload() {
		return nil, true, errors.New("crypto exchange route is unavailable or not authorized")
	}
	if info.PayloadTypeMessageUUIDLength != uuidSize {
		return nil, true, errors.New("crypto provider UUID framing mismatch")
	}
	if len(exchange.Response) > 0 {
		return exchange.Response, true, nil
	}
	if lookupRoute == route {
		// The original route is still active; normal dispatch can resume its
		// deterministic request without allocating another exchange.
		return nil, false, nil
	}
	local := providerRequestCache(info, exchange.RequestID)
	local.UUID = route
	local.UUIDType = UUIDTYPESTAGING
	encoded, err := processCryptoProviderEstablishment(local, body, uuidSize, remoteIP, getMessageProcessingAuthContext(local, auth))
	return encoded, true, err
}

// Complete the same routing metadata as ordinary check-in dispatch. Push C2 and
// recursive delegates need this independently of the response's staging prefix.
func populateCryptoProviderResponseMetadata(response *recursiveProcessAgentMessageResponse, route string, body []byte) error {
	response.OuterUuid = route
	var callbackUUID string
	err := database.DB.Get(&callbackUUID, `SELECT callback.agent_callback_id
		FROM crypto_provider_exchange e JOIN callback ON callback.crypto_provider_binding_id=e.binding_id
		WHERE e.route_uuid=$1 AND e.input_digest=$2`, route, cryptoPacketDigest(body))
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		response.Message = nil
		return err
	}
	response.OuterUuidIsCallback = callbackUUID == route
	if !response.OuterUuidIsCallback {
		response.NewCallbackUUID = callbackUUID
	}
	return nil
}
