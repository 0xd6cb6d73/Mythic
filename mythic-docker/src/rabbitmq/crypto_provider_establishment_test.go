package rabbitmq

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
	"github.com/jmoiron/sqlx"
)

func TestCryptoProviderFramePreservesOpaqueBytes(t *testing.T) {
	route := uuid.NewString()
	body := []byte{0, 0xff, 0x80, 1, 2}
	for _, width := range []int{16, 36} {
		encoded, err := providerFrame(route, body, width)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		prefix, _ := GetUUIDBytes(route, width)
		if !bytes.Equal(raw, append(prefix, body...)) {
			t.Fatalf("UUID%d changed the opaque body: %x", width, raw)
		}
	}
	for _, test := range []struct {
		route string
		width int
	}{{"invalid", 36}, {"invalid", 16}, {route, 32}} {
		if _, err := providerFrame(test.route, body, test.width); err == nil {
			t.Fatalf("accepted invalid frame route=%q width=%d", test.route, test.width)
		}
	}
}

func establishmentProviderTestDB(t *testing.T, width int) (*sqlx.DB, *cachedUUIDInfo) {
	t.Helper()
	db := callbackProviderTestDB(t)
	previousDB, previousCall, previousNotify := database.DB, callCryptoProvider, notifyCryptoProviderCallbackCreated
	database.DB = db
	cachedUUIDInfoMapMutex.Lock()
	previousCache := cachedUUIDInfoMap
	cachedUUIDInfoMap = make(map[string]*cachedUUIDInfo)
	cachedUUIDInfoMapMutex.Unlock()
	t.Cleanup(func() {
		database.DB, callCryptoProvider, notifyCryptoProviderCallbackCreated = previousDB, previousCall, previousNotify
		cachedUUIDInfoMapMutex.Lock()
		cachedUUIDInfoMap = previousCache
		cachedUUIDInfoMapMutex.Unlock()
	})
	_, err := db.Exec(`
		ALTER TABLE crypto_provider_binding
			ADD COLUMN profile_id uuid, ADD COLUMN provider_id integer NOT NULL DEFAULT 1,
			ADD COLUMN profile_ref text NOT NULL DEFAULT '', ADD COLUMN namespace text NOT NULL DEFAULT '',
			ADD COLUMN state_id text NOT NULL DEFAULT '', ADD COLUMN provider_json jsonb NOT NULL DEFAULT '{}',
			ADD COLUMN agent_config bytea, ADD COLUMN enc_key bytea, ADD COLUMN dec_key bytea;
		ALTER TABLE staginginfo ADD COLUMN session_id text, ADD COLUMN crypto_type text, ADD COLUMN enc_key bytea, ADD COLUMN dec_key bytea, ADD CONSTRAINT stage_route_unique UNIQUE(staging_uuid);
		ALTER TABLE crypto_provider_exchange ADD COLUMN input_digest text, ADD COLUMN response bytea, ADD COLUMN session_binding_id uuid, ADD COLUMN seal_input bytea,
			ADD CONSTRAINT exchange_packet_unique UNIQUE(binding_id,route_uuid,input_digest);
		ALTER TABLE callback ADD COLUMN last_checkin timestamptz NOT NULL DEFAULT now(), ADD COLUMN trigger_on_checkin_after_time integer NOT NULL DEFAULT 0;
		CREATE TABLE consuming_container (id integer PRIMARY KEY, name text, type text, deleted boolean);
		CREATE TABLE operation (id integer PRIMARY KEY, complete boolean, name text, webhook text, channel text);
		CREATE TABLE operator (id integer PRIMARY KEY, username text);
		CREATE TABLE payloadtype (id integer PRIMARY KEY, name text, mythic_encrypts boolean, translation_container_id integer,
			message_format text, message_uuid_length integer);
		CREATE TABLE payload (id integer PRIMARY KEY, uuid uuid, operator_id integer, description text, callback_alert boolean, os text,
			operation_id integer, payload_type_id integer, deleted boolean DEFAULT false, callback_allowed boolean DEFAULT true);
		CREATE TABLE c2profileparameters (id integer PRIMARY KEY, c2_profile_id integer, crypto_type boolean);
		CREATE TABLE buildparameterinstance (id serial PRIMARY KEY, payload_id integer, enc_key bytea, dec_key bytea,
			value text, crypto_provider_binding_id uuid);
		INSERT INTO consuming_container VALUES (1,'test-provider','crypto',false);
		INSERT INTO operation VALUES (17,false,'test operation','','');
		INSERT INTO operator VALUES (7,'operator');
		INSERT INTO c2profile VALUES (31,'test-c2',true);
		INSERT INTO payloadc2profiles VALUES (23,31);
		INSERT INTO c2profileparameters VALUES (61,31,true);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO payloadtype VALUES (1,'test-agent',true,NULL,'json',$1)`, width); err != nil {
		t.Fatal(err)
	}
	profileID, payloadUUID := uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(`INSERT INTO payload VALUES (23,$1,7,'test payload',false,'linux',17,1,false,true)`, payloadUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref,profile_ref)
		VALUES ($1,17,'test-scheme','','opaque-profile')`, profileID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO c2profileparametersinstance
		(c2_profile_parameters_id,c2_profile_id,value,payload_id,crypto_provider_binding_id)
		VALUES (61,31,'provider:test-provider:test-scheme',23,$1)`, profileID); err != nil {
		t.Fatal(err)
	}
	info, err := LookupEncryptionData("test-c2", payloadUUID, false)
	if err != nil {
		t.Fatal(err)
	}
	return db, info
}

func TestCryptoProviderEstablishmentRejectsWithoutAllocatingRows(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	var requestIDs []string
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		requestIDs = append(requestIDs, request.RequestID)
		return nil, errors.New("invalid registration")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := processCryptoProviderEstablishment(info, []byte("untrusted registration"), 36, "", RabbitMQAuthContext{OperationID: 17}); err == nil {
			t.Fatal("rejected registration succeeded")
		}
	}
	var count int
	if err := db.Get(&count, `SELECT count(*) FROM crypto_provider_exchange`); err != nil || count != 0 {
		t.Fatalf("untrusted registration allocated %d exchange rows: %v", count, err)
	}
	if len(requestIDs) != 2 || requestIDs[0] != requestIDs[1] {
		t.Fatalf("retry did not preserve its deterministic request ID: %v", requestIDs)
	}
}

func TestCryptoProviderEstablishmentRetryAndCallbackRecovery(t *testing.T) {
	for _, width := range []int{16, 36} {
		t.Run(fmt.Sprintf("UUID%d", width), func(t *testing.T) {
			db, info := establishmentProviderTestDB(t, width)
			notifications := 0
			notifyCryptoProviderCallbackCreated = func(databaseStructs.Callback, databaseStructs.Payload, RabbitMQAuthContext) { notifications++ }
			journal := make(map[string]provider.Response)
			digests := make(map[string]string)
			calls := make(map[string]int)
			loseInitialReply := true
			callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
				calls[request.Method]++
				digest, err := request.Digest()
				if err != nil {
					return nil, err
				}
				if old, ok := digests[request.RequestID]; ok && old != digest {
					return nil, fmt.Errorf("idempotency conflict for %s", request.Method)
				}
				digests[request.RequestID] = digest
				response, ok := journal[request.RequestID]
				if !ok {
					response = provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
						OperationScopeID: request.OperationScopeID, Success: true}
					switch request.Method {
					case provider.BeginSession:
						response.SessionRef, response.Namespace, response.StateID = "opaque-session", "owner", "shared-state"
						response.Message = []byte(`{"provider_handshake":"opaque"}`)
					case provider.Open:
						response.Message = []byte(fmt.Sprintf(`{"action":"checkin","uuid":%q,"host":"HOST","user":"alice"}`, info.PayloadUUID))
					case provider.Seal:
						response.Message = append([]byte("opaque-sealed:"), request.Message...)
					default:
						return nil, errors.New("unexpected fake provider operation")
					}
					journal[request.RequestID] = response
				}
				response.AuthContext = request.AuthContext
				if request.Method == provider.BeginSession && loseInitialReply {
					loseInitialReply = false
					return nil, errors.New("accepted registration reply was lost")
				}
				return &response, nil
			}
			registration := []byte("opaque provider registration")
			incoming, _ := providerFrame(info.UUID, registration, width)
			first := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &incoming, C2Profile: "test-c2"})
			if first.Err == nil {
				t.Fatal("expected lost initial response")
			}
			second := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &incoming, C2Profile: "test-c2"})
			if second.Err != nil {
				t.Fatal(second.Err)
			}
			third := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &incoming, C2Profile: "test-c2"})
			if third.Err != nil || !bytes.Equal(second.Message, third.Message) || calls[provider.BeginSession] != 2 {
				t.Fatalf("registration retry was not byte-identical: %v, calls=%v", third.Err, calls)
			}
			var stage string
			if err := db.Get(&stage, `SELECT staging_uuid FROM staginginfo`); err != nil {
				t.Fatal(err)
			}
			protectedCheckin := []byte("opaque protected checkin")
			stagedInput, _ := providerFrame(stage, protectedCheckin, width)
			checkedIn := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &stagedInput, C2Profile: "test-c2", TrackingID: "push-connection"})
			if checkedIn.Err != nil {
				t.Fatal(checkedIn.Err)
			}
			if checkedIn.NewCallbackUUID == "" || checkedIn.OuterUuid != stage || checkedIn.OuterUuidIsCallback || checkedIn.AgentUUIDSize != width || checkedIn.TrackingID != "push-connection" {
				t.Fatalf("push/delegate transition metadata was lost: %+v", checkedIn)
			}
			plainFrame, err := base64.StdEncoding.DecodeString(string(checkedIn.Message))
			prefix, _ := GetUUIDBytes(stage, width)
			if err != nil || !bytes.HasPrefix(plainFrame, prefix) {
				t.Fatalf("check-in response changed the incoming staging envelope: %x, %v", plainFrame, err)
			}
			if _, err := db.Exec(`UPDATE crypto_provider_exchange SET response=NULL WHERE binding_id=$1`, stage); err != nil {
				t.Fatal(err)
			}
			InvalidateAllCachedUUIDInfo()
			recovered := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &stagedInput, C2Profile: "test-c2"})
			if recovered.Err != nil || recovered.NewCallbackUUID != checkedIn.NewCallbackUUID || !bytes.Equal(recovered.Message, checkedIn.Message) || notifications != 1 {
				t.Fatalf("callback recovery changed the result: err=%v callback=%s notifications=%d", recovered.Err, recovered.NewCallbackUUID, notifications)
			}
			if calls[provider.Open] != 1 || calls[provider.Seal] != 2 {
				t.Fatalf("recovery did not retrieve original crypto results: %v", calls)
			}
			var callbacks, stages int
			db.Get(&callbacks, `SELECT count(*) FROM callback`)
			db.Get(&stages, `SELECT count(*) FROM staginginfo`)
			if callbacks != 1 || stages != 0 {
				t.Fatalf("recovery duplicated lifecycle effects: callbacks=%d stages=%d", callbacks, stages)
			}
		})
	}
}

func TestCryptoProviderCheckinRecoversLostSealWithoutReopening(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	notifications, opens, seals := 0, 0, 0
	notifyCryptoProviderCallbackCreated = func(databaseStructs.Callback, databaseStructs.Payload, RabbitMQAuthContext) { notifications++ }
	var sealRequestID, sealDigest string
	var protectedResponse, sealPlaintext []byte
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		response := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
			OperationScopeID: request.OperationScopeID, Success: true, AuthContext: request.AuthContext}
		switch request.Method {
		case provider.BeginSession:
			response.SessionRef, response.Namespace, response.StateID = "opaque-session", "owner", "shared-state"
			response.Message = []byte("opaque handshake")
		case provider.Open:
			opens++
			response.Message = []byte(fmt.Sprintf(`{"action":"checkin","uuid":%q,"host":"HOST"}`, info.PayloadUUID))
		case provider.Seal:
			seals++
			digest, err := request.Digest()
			if err != nil {
				return nil, err
			}
			if seals == 1 {
				sealRequestID, sealDigest = request.RequestID, digest
				sealPlaintext = bytes.Clone(request.Message)
				protectedResponse = append([]byte("committed seal:"), request.Message...)
				return nil, errors.New("seal committed but reply was lost")
			}
			if request.RequestID != sealRequestID || digest != sealDigest {
				return nil, errors.New("seal recovery changed the committed request")
			}
			response.Message = protectedResponse
		default:
			return nil, errors.New("unexpected fake provider operation")
		}
		return response, nil
	}
	if _, err := processCryptoProviderEstablishment(info, []byte("registration"), 36, "", RabbitMQAuthContext{OperationID: 17}); err != nil {
		t.Fatal(err)
	}
	var stage string
	if err := db.Get(&stage, `SELECT staging_uuid FROM staginginfo`); err != nil {
		t.Fatal(err)
	}
	incoming, _ := providerFrame(stage, []byte("protected checkin"), 36)
	first := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &incoming, C2Profile: "test-c2"})
	if first.Err == nil {
		t.Fatal("expected the lost seal reply to remain unresolved")
	}
	var pending struct {
		SealInput []byte `db:"seal_input"`
		Response  []byte `db:"response"`
	}
	if err := db.Get(&pending, `SELECT seal_input,response FROM crypto_provider_exchange WHERE binding_id=$1 AND route_uuid=$1`, stage); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending.SealInput, sealPlaintext) || len(pending.Response) != 0 {
		t.Fatalf("lost seal did not retain its exact input without a response: %+v", pending)
	}
	InvalidateAllCachedUUIDInfo()
	recovered := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &incoming, C2Profile: "test-c2"})
	if recovered.Err != nil || recovered.NewCallbackUUID == "" {
		t.Fatalf("could not recover the committed seal: callback=%q err=%v", recovered.NewCallbackUUID, recovered.Err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(recovered.Message))
	if err != nil || len(raw) < 36 || string(raw[:36]) != stage || !bytes.Equal(raw[36:], protectedResponse) {
		t.Fatalf("recovery changed the committed protected response: %x, %v", raw, err)
	}
	if opens != 1 || seals != 2 || notifications != 1 {
		t.Fatalf("recovery repeated earlier work: opens=%d seals=%d notifications=%d", opens, seals, notifications)
	}
	if err := db.Get(&pending, `SELECT seal_input,response FROM crypto_provider_exchange WHERE binding_id=$1 AND route_uuid=$1`, stage); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pending.SealInput, sealPlaintext) || !bytes.Equal(pending.Response, recovered.Message) {
		t.Fatalf("successful recovery did not retain the original exchange: %+v", pending)
	}
}

func TestCryptoProviderCachedReplyRevalidatesRouting(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	body := []byte("known registration")
	exchange, err := cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, body)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := providerFrame(info.UUID, []byte("original response"), 36)
	if _, err := db.Exec(`INSERT INTO crypto_provider_exchange(binding_id,route_uuid,input_digest,request_id,next_uuid,response)
		VALUES($1,$2,$3,$4,$5,$6)`, exchange.BindingID, exchange.RouteUUID, exchange.InputDigest, exchange.RequestID, exchange.NextUUID, encoded); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, c2     string
		width, scope int
		allowed      bool
	}{
		{"wrong frame", "test-c2", 16, 17, true},
		{"wrong operation", "test-c2", 36, 18, true},
		{"unknown C2", "missing-c2", 36, 17, true},
		{"disabled payload", "test-c2", 36, 17, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			info.stateMutex.Lock()
			info.CallbackAllowedFromPayload = test.allowed
			info.stateMutex.Unlock()
			if response, found, err := cachedCryptoProviderExchange(info.UUID, body, test.c2, RabbitMQAuthContext{OperationID: test.scope}, test.width, ""); err == nil || !found || len(response) != 0 {
				t.Fatalf("cached reply bypassed routing validation: found=%v err=%v", found, err)
			}
		})
	}
	info.stateMutex.Lock()
	info.CallbackAllowedFromPayload = true
	info.stateMutex.Unlock()
	if response, found, err := cachedCryptoProviderExchange(info.UUID, body, "test-c2", RabbitMQAuthContext{OperationID: 17}, 36, ""); err != nil || !found || !bytes.Equal(response, encoded) {
		t.Fatalf("authorized cached reply was not preserved: found=%v err=%v", found, err)
	}
	callCryptoProvider = func(string, provider.Request) (*provider.Response, error) {
		t.Fatal("cached reply invoked the provider")
		return nil, nil
	}
	frame, err := providerFrame(info.UUID, body, 36)
	if err != nil {
		t.Fatal(err)
	}
	replayed := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &frame, C2Profile: "test-c2",
		AuthContext: RabbitMQAuthContext{OperationID: 17}})
	if replayed.Err != nil || !bytes.Equal(replayed.Message, encoded) {
		t.Fatalf("cached reply changed: %v", replayed.Err)
	}
}
