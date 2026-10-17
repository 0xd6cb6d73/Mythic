package rabbitmq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	mythicCrypto "github.com/its-a-feature/Mythic/crypto"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	amqp "github.com/rabbitmq/amqp091-go"
)

// callCryptoProvider is replaceable in package tests; production always uses
// the same serialized request body across AMQP publish/timeout retries.
var callCryptoProvider = sendCryptoProviderRequest

func sendCryptoProviderRequest(name string, request provider.Request) (*provider.Response, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	route, err := provider.RoutingKey(name)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	authContext, err := ValidateRabbitMQAuthContextToken(request.AuthContext)
	if err != nil || authContext.ContainerName != name || authContext.OperationID != request.OperationScopeID {
		return nil, errors.New("crypto provider authorization context mismatch")
	}
	headers := amqp.Table{MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER: request.AuthContext}
	responseBytes, err := RabbitMQConnection.SendRPCMessage(MYTHIC_EXCHANGE, route, body, false, RPC_RETRY_POLICY_RETRY_ON_TIMEOUT, headers)
	if err != nil {
		return nil, errors.New("crypto provider unavailable or request outcome unresolved")
	}
	if len(responseBytes) > provider.MaxMessageBytes*2 {
		return nil, errors.New("crypto provider response exceeds limit")
	}
	var response provider.Response
	if err = json.Unmarshal(responseBytes, &response); err != nil {
		return nil, errors.New("invalid crypto provider response")
	}
	if err = response.Validate(request); err != nil {
		return nil, err
	}
	return &response, nil
}

// Authorization context exists only while the synchronous request is in flight.
// Durable outcomes must never retain a process-local authorization handle.
func invokeCryptoProvider(name string, request provider.Request) (*provider.Response, error) {
	defer InvalidateRabbitMQAuthContextToken(request.AuthContext)
	if err := request.Validate(); err != nil {
		return nil, err
	}
	response, err := callCryptoProvider(name, request)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("empty crypto provider response")
	}
	if err = ValidateRabbitMQAuthContextResponseToken(request.AuthContext, response.AuthContext); err != nil {
		return nil, err
	}
	if err = response.Validate(request); err != nil {
		return nil, err
	}
	return response, nil
}

func loadCryptoProviderBinding(id string, operationID int) (*provider.Binding, error) {
	var binding provider.Binding
	err := database.DB.Get(&binding, `SELECT b.id,b.provider_id,c.name provider_name,b.operation_id,b.scheme,b.profile_ref,b.session_ref,b.namespace,b.state_id,b.provider_json,b.agent_config,b.enc_key,b.dec_key
		FROM crypto_provider_binding b JOIN consuming_container c ON c.id=b.provider_id
		WHERE b.id=$1 AND b.operation_id=$2 AND c.type='crypto' AND NOT c.deleted`, id, operationID)
	if err != nil {
		return nil, errors.New("crypto provider binding unavailable")
	}
	return &binding, nil
}

func requestForBinding(binding *provider.Binding, method string, message []byte, requestID string, authContext RabbitMQAuthContext) (provider.Request, error) {
	if binding == nil || binding.OperationScopeID <= 0 || authContext.OperationID != binding.OperationScopeID {
		return provider.Request{}, errors.New("crypto provider operation mismatch")
	}
	// Bind the normal, transient Mythic RPC context to the selected service.
	// Storage calls may only use it on behalf of that registered container.
	authContext.ContainerName = binding.ProviderName
	token, err := GenerateRabbitMQAuthContextToken(authContext)
	if err != nil {
		return provider.Request{}, err
	}
	if requestID == "" {
		requestID = uuid.NewString()
	}
	return provider.Request{APIVersion: provider.APIVersion, RequestID: requestID, OperationScopeID: binding.OperationScopeID, Method: method, Scheme: binding.Scheme, ProfileRef: binding.ProfileRef, SessionRef: binding.SessionRef, Namespace: binding.Namespace, StateID: binding.StateID, ProviderJSON: binding.ProviderJSON, Message: message, AuthContext: token}, nil
}

func cryptoProviderAct(binding *provider.Binding, action string, message []byte, requestID string, authContext RabbitMQAuthContext) ([]byte, error) {
	method := provider.Open
	if action == "encrypt" {
		method = provider.Seal
	} else if action != "decrypt" {
		return nil, errors.New("unknown crypto action")
	}
	if binding == nil || binding.SessionRef == "" || binding.ID == "" {
		return nil, errors.New("crypto provider session has not been established")
	}
	request, err := requestForBinding(binding, method, message, requestID, authContext)
	if err != nil {
		return nil, err
	}
	// The provider owns native state serialization and recovery. Mythic only
	// correlates the opaque request and propagates the provider's outcome.
	response, err := invokeCryptoProvider(binding.ProviderName, request)
	if err != nil {
		return nil, err
	}
	return response.Message, nil
}

func PrepareCryptoProviderKeys(value string, operationID int, authContext RabbitMQAuthContext) (mythicCrypto.CryptoKeys, error) {
	name, scheme, external, err := provider.ParseSelection(value)
	if err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	if !external {
		return mythicCrypto.GenerateKeysForPayload(value)
	}
	if authContext.OperationID != operationID || operationID <= 0 {
		return mythicCrypto.CryptoKeys{}, errors.New("crypto provider operation mismatch")
	}
	var registration struct {
		ID           int    `db:"id"`
		Capabilities []byte `db:"crypto_capabilities"`
	}
	if err = database.DB.Get(&registration, `SELECT id,crypto_capabilities FROM consuming_container WHERE name=$1 AND type='crypto' AND NOT deleted AND container_running`, name); err != nil {
		return mythicCrypto.CryptoKeys{}, errors.New("crypto provider unavailable")
	}
	var capabilities provider.Capabilities
	if err = json.Unmarshal(registration.Capabilities, &capabilities); err != nil {
		return mythicCrypto.CryptoKeys{}, errors.New("invalid crypto provider capabilities")
	}
	if err = capabilities.Validate(); err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	if !capabilities.Supports(scheme) {
		return mythicCrypto.CryptoKeys{}, errors.New("crypto scheme not supported by selected provider")
	}
	binding := &provider.Binding{ProviderID: registration.ID, ProviderName: name, OperationScopeID: operationID, Scheme: scheme, ProviderJSON: json.RawMessage(`{}`)}
	request, err := requestForBinding(binding, provider.PrepareProfile, nil, "", authContext)
	if err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	response, err := invokeCryptoProvider(name, request)
	if err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	if err = response.Validate(request); err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	config := response.AgentConfig
	// Agent configuration is opaque binary; builder JSON carries it as base64.
	projectedConfig := encodeCryptoProviderAgentConfig(config)
	providerJSON := response.ProviderJSON
	if len(providerJSON) == 0 {
		providerJSON = json.RawMessage(`{}`)
	}
	bindingID := uuid.NewString()
	_, err = database.DB.Exec(`INSERT INTO crypto_provider_binding(id,provider_id,operation_id,scheme,profile_ref,namespace,state_id,provider_json,agent_config,enc_key,dec_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, bindingID, registration.ID, operationID, scheme, response.ProfileRef, response.Namespace, response.StateID, []byte(providerJSON), config, response.EncKey, response.DecKey)
	if err != nil {
		return mythicCrypto.CryptoKeys{}, fmt.Errorf("save crypto provider profile: %w", err)
	}
	return mythicCrypto.CryptoKeys{Value: value, EncKey: response.EncKey, DecKey: response.DecKey, BindingID: &bindingID, ProviderConfig: projectedConfig}, nil
}

// Storage uses the incoming request's transient Mythic RPC authorization context.
// Provider identity is resolved from that context, never from a body claim alone.
const cryptoProviderStorageRoute = "mythic_rpc_crypto_provider_storage"

type cryptoProviderStorageRequest struct {
	APIVersion   int             `json:"api_version"`
	RequestID    string          `json:"request_id"`
	ProviderName string          `json:"provider_name"`
	Method       string          `json:"method"`
	Input        json.RawMessage `json:"input"`
}

type cryptoProviderStorageResponse struct {
	APIVersion   int               `json:"api_version"`
	RequestID    string            `json:"request_id"`
	ProviderName string            `json:"provider_name"`
	Success      bool              `json:"success"`
	Result       interface{}       `json:"result,omitempty"`
	Error        *provider.Failure `json:"error,omitempty"`
}

func init() {
	RabbitMQConnection.AddRPCQueue(RPCQueueStruct{Exchange: MYTHIC_EXCHANGE, Queue: cryptoProviderStorageRoute, RoutingKey: cryptoProviderStorageRoute, Handler: processCryptoProviderStorage, Scopes: []string{}})
}

func processCryptoProviderStorage(msg amqp.Delivery) interface{} {
	unauthorized := func() interface{} {
		return map[string]interface{}{"success": false, "error": "invalid crypto storage authorization context"}
	}
	authContext, err := GetRabbitMQAuthContextFromHeaders(msg.Headers)
	if err != nil || authContext.ContainerName == "" || authContext.OperationID <= 0 {
		return unauthorized()
	}
	var input cryptoProviderStorageRequest
	if len(msg.Body) > provider.MaxMessageBytes*2 || json.Unmarshal(msg.Body, &input) != nil || input.APIVersion != provider.APIVersion || input.ProviderName != authContext.ContainerName {
		return unauthorized()
	}
	id, err := uuid.Parse(input.RequestID)
	if err != nil || id.String() != input.RequestID {
		return unauthorized()
	}
	response := cryptoProviderStorageResponse{APIVersion: provider.APIVersion, RequestID: input.RequestID, ProviderName: input.ProviderName}
	var providerID int
	err = database.DB.Get(&providerID, `SELECT id FROM consuming_container WHERE name=$1 AND type='crypto' AND NOT deleted`, authContext.ContainerName)
	if err != nil {
		response.Error = &provider.Failure{Code: "unauthorized", Message: "crypto provider is not registered"}
		return response
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := provider.NewStore(database.DB)
	switch input.Method {
	case "load":
		var req provider.StateKey
		if err = json.Unmarshal(input.Input, &req); err == nil {
			response.Result, err = store.Load(ctx, providerID, req)
		}
	case "create":
		var req provider.CreateStateRequest
		if err = json.Unmarshal(input.Input, &req); err == nil {
			response.Result, err = store.Create(ctx, providerID, req)
		}
	case "acquire":
		var req provider.AcquireStateRequest
		if err = json.Unmarshal(input.Input, &req); err == nil {
			response.Result, err = store.Acquire(ctx, providerID, req)
		}
	case "commit":
		var req provider.CommitStateRequest
		if err = json.Unmarshal(input.Input, &req); err == nil {
			response.Result, err = store.Commit(ctx, providerID, req)
		}
	case "get_result":
		var req provider.LookupResultRequest
		if err = json.Unmarshal(input.Input, &req); err == nil {
			response.Result, err = store.LookupResult(ctx, providerID, req)
		}
	default:
		err = provider.ErrInvalidInput
	}
	if err != nil {
		response.Result = nil
		response.Error = cryptoProviderStorageFailure(err)
	} else {
		response.Success = true
	}
	return response
}

func cryptoProviderStorageFailure(err error) *provider.Failure {
	code := "internal_error"
	message := "crypto provider storage unavailable"
	for _, entry := range []struct {
		cause error
		code  string
	}{
		{provider.ErrInvalidInput, "invalid_input"}, {provider.ErrNotFound, "not_found"},
		{provider.ErrAlreadyExists, "already_exists"}, {provider.ErrStaleWriter, "stale_writer"},
		{provider.ErrRequestConflict, "request_conflict"},
	} {
		if errors.Is(err, entry.cause) {
			code, message = entry.code, entry.cause.Error()
			break
		}
	}
	var syntax *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &syntax) || errors.As(err, &typeError) {
		code, message = "invalid_input", "invalid crypto provider storage input"
	}
	return &provider.Failure{Code: code, Message: message}
}

// Provider selection completes before any stateful request. A legacy fallback
// and a custom session cannot be tried against the same incoming ciphertext.
type cryptoProviderCandidate struct {
	BindingID string `db:"binding_id"`
	Value     string `db:"value"`
}

func selectCryptoProviderBinding(candidates []cryptoProviderCandidate) (string, error) {
	selected := ""
	legacy := false
	for _, candidate := range candidates {
		if candidate.BindingID == "" {
			if strings.HasPrefix(candidate.Value, "provider:") {
				return "", errors.New("crypto provider binding unavailable")
			}
			legacy = legacy || (candidate.Value != "" && candidate.Value != "none")
			continue
		}
		if selected != "" && selected != candidate.BindingID {
			return "", errors.New("ambiguous crypto provider selection")
		}
		selected = candidate.BindingID
	}
	if selected != "" && legacy {
		return "", errors.New("ambiguous legacy and custom crypto selection")
	}
	return selected, nil
}

// A public callback-create RPC cannot manufacture an authenticated provider
// session through legacy key inference. The selected transport is considered
// independently so payloads can still have unrelated legacy C2 routes.
func payloadRouteUsesCryptoProvider(payloadID int, c2 string) (bool, error) {
	var managed bool
	err := database.DB.Get(&managed, `SELECT EXISTS (
		SELECT 1 FROM buildparameterinstance WHERE payload_id=$1 AND crypto_provider_binding_id IS NOT NULL
		UNION ALL
		SELECT 1 FROM c2profileparametersinstance i JOIN c2profile c ON c.id=i.c2_profile_id
		WHERE i.payload_id=$1 AND i.crypto_provider_binding_id IS NOT NULL AND ($2='' OR c.name=$2))`, payloadID, c2)
	return managed, err
}

func validatePayloadCryptoProviderSelections(payloadID int) error {
	var hasProvider bool
	err := database.DB.Get(&hasProvider, `SELECT EXISTS (
		SELECT 1 FROM buildparameterinstance WHERE payload_id=$1 AND crypto_provider_binding_id IS NOT NULL
		UNION ALL SELECT 1 FROM c2profileparametersinstance WHERE payload_id=$1 AND crypto_provider_binding_id IS NOT NULL)`, payloadID)
	if err != nil || !hasProvider {
		return err
	}
	build := []cryptoProviderCandidate{}
	err = database.DB.Select(&build, `SELECT value,COALESCE(crypto_provider_binding_id::text,'') binding_id
		FROM buildparameterinstance WHERE payload_id=$1 AND (dec_key IS NOT NULL OR crypto_provider_binding_id IS NOT NULL)`, payloadID)
	if err != nil {
		return err
	}
	if _, err = selectCryptoProviderBinding(build); err != nil {
		return err
	}
	var profiles []int
	if err = database.DB.Select(&profiles, `SELECT c2_profile_id FROM payloadc2profiles WHERE payload_id=$1`, payloadID); err != nil {
		return err
	}
	for _, profileID := range profiles {
		candidates := append([]cryptoProviderCandidate{}, build...)
		var c2 []cryptoProviderCandidate
		err = database.DB.Select(&c2, `SELECT i.value,COALESCE(i.crypto_provider_binding_id::text,'') binding_id
			FROM c2profileparametersinstance i JOIN c2profileparameters p ON p.id=i.c2_profile_parameters_id
			WHERE i.payload_id=$1 AND i.c2_profile_id=$2 AND p.crypto_type`, payloadID, profileID)
		if err != nil {
			return err
		}
		if _, err = selectCryptoProviderBinding(append(candidates, c2...)); err != nil {
			return err
		}
	}
	return nil
}
