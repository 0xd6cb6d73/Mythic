package rabbitmq

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
)

func TestCryptoProviderRPCFailureLeavesSessionPolicyToProvider(t *testing.T) {
	previousDB, previousCall := database.DB, callCryptoProvider
	database.DB = nil
	t.Cleanup(func() { database.DB, callCryptoProvider = previousDB, previousCall })
	binding := &provider.Binding{ID: uuid.NewString(), ProviderName: "worker", OperationScopeID: 17, Scheme: "example", SessionRef: "opaque-session", Namespace: "sessions"}
	var originalRequest provider.Request
	calls := 0
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		calls++
		originalRequest = request
		return nil, errors.New("reply lost after worker committed")
	}
	if _, err := cryptoProviderAct(binding, "encrypt", []byte("plaintext"), "", RabbitMQAuthContext{OperationID: 17}); err == nil {
		t.Fatal("ambiguous reply accepted")
	}
	if _, err := ValidateRabbitMQAuthContextToken(originalRequest.AuthContext); err == nil {
		t.Fatal("completed RPC retained its transient authorization token")
	}
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		calls++
		return &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, Success: true, Message: []byte{0, 255, 128}, AuthContext: request.AuthContext}, nil
	}
	// The provider owns recovery and whether this session can accept fresh work.
	// These calls deliberately have no Mythic database available.
	for _, requestID := range []string{originalRequest.RequestID, ""} {
		got, err := cryptoProviderAct(binding, "encrypt", []byte("plaintext"), requestID, RabbitMQAuthContext{OperationID: 17})
		if err != nil || string(got) != string([]byte{0, 255, 128}) {
			t.Fatalf("provider outcome was overridden by server policy: result=%x err=%v", got, err)
		}
	}
	if calls != 3 {
		t.Fatalf("provider did not receive recovery and fresh calls: %d", calls)
	}
}

func TestCryptoProviderRejectedInputKeepsSessionUsable(t *testing.T) {
	db := callbackProviderTestDB(t)
	previousDB, previousCall := database.DB, callCryptoProvider
	database.DB = db
	t.Cleanup(func() { database.DB, callCryptoProvider = previousDB, previousCall })
	binding := &provider.Binding{ID: uuid.NewString(), ProviderName: "worker", OperationScopeID: 17, Scheme: "example", SessionRef: "session", Namespace: "sessions"}
	if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref) VALUES ($1,17,'example','session')`, binding.ID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		calls++
		return &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: 17, AuthContext: request.AuthContext, Error: &provider.Failure{Code: "authentication_failed", Message: "rejected", Outcome: "rejected"}}, nil
	}
	for i := 0; i < 2; i++ {
		_, err := cryptoProviderAct(binding, "decrypt", []byte("invalid packet"), "", RabbitMQAuthContext{OperationID: 17})
		var failure *provider.Failure
		if !errors.As(err, &failure) {
			t.Fatalf("definitive rejection changed into unresolved state: %v", err)
		}
	}
	if calls != 2 {
		t.Fatalf("rejected input disabled session: calls=%d", calls)
	}
}

func TestCryptoProviderRequestBindsTransientContextToContainer(t *testing.T) {
	binding := &provider.Binding{ProviderName: "worker", OperationScopeID: 17, Scheme: "example"}
	original := RabbitMQAuthContext{OperationID: 17, OperatorID: 23, ContainerName: "other-container"}
	request, err := requestForBinding(binding, provider.PrepareProfile, nil, "", original)
	if err != nil {
		t.Fatal(err)
	}
	defer InvalidateRabbitMQAuthContextToken(request.AuthContext)
	auth, err := ValidateRabbitMQAuthContextToken(request.AuthContext)
	if err != nil || auth.ContainerName != "worker" || auth.OperationID != 17 || auth.OperatorID != 23 {
		t.Fatalf("request context does not identify selected provider and campaign: %+v %v", auth, err)
	}
	if original.ContainerName != "other-container" {
		t.Fatal("request mutated caller's authorization context")
	}
	if _, err := requestForBinding(binding, provider.PrepareProfile, nil, "", RabbitMQAuthContext{OperationID: 18}); err == nil {
		t.Fatal("cross-campaign provider request accepted")
	}
}

func TestCryptoProviderRejectsReplyAfterContextInvalidation(t *testing.T) {
	previous := callCryptoProvider
	t.Cleanup(func() { callCryptoProvider = previous })
	binding := &provider.Binding{ProviderName: "worker", OperationScopeID: 17, Scheme: "example"}
	request, err := requestForBinding(binding, provider.Describe, nil, "", RabbitMQAuthContext{OperationID: 17})
	if err != nil {
		t.Fatal(err)
	}
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		InvalidateRabbitMQAuthContextToken(request.AuthContext)
		return &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true}, nil
	}
	if _, err := invokeCryptoProvider("worker", request); err == nil {
		t.Fatal("accepted a response after its authorization context was revoked")
	}
}

func TestCryptoProviderInvocationValidatesBeforeTransport(t *testing.T) {
	previous := callCryptoProvider
	t.Cleanup(func() { callCryptoProvider = previous })
	callCryptoProvider = func(string, provider.Request) (*provider.Response, error) {
		t.Fatal("invalid request reached provider transport")
		return nil, nil
	}
	for _, test := range []struct {
		name   string
		mutate func(*provider.Request)
	}{
		{"invalid request", func(r *provider.Request) { r.RequestID = "invalid" }},
		{"wrong operation", func(r *provider.Request) { r.OperationScopeID++ }},
		{"wrong container", func(r *provider.Request) {
			InvalidateRabbitMQAuthContextToken(r.AuthContext)
			token, err := GenerateRabbitMQAuthContextToken(RabbitMQAuthContext{OperationID: 17, ContainerName: "another-worker"})
			if err != nil {
				t.Fatal(err)
			}
			r.AuthContext = token
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := requestForBinding(&provider.Binding{ProviderName: "worker", OperationScopeID: 17, Scheme: "example"}, provider.PrepareProfile, nil, "", RabbitMQAuthContext{OperationID: 17})
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&request)
			if _, err := invokeCryptoProvider("worker", request); err == nil {
				t.Fatal("invalid provider invocation accepted")
			}
			if _, err := ValidateRabbitMQAuthContextToken(request.AuthContext); err == nil {
				t.Fatal("failed invocation retained its transient authorization token")
			}
		})
	}
}

func TestCryptoProviderInvocationValidatesCorrelatedResponse(t *testing.T) {
	previous := callCryptoProvider
	t.Cleanup(func() { callCryptoProvider = previous })
	for _, test := range []struct {
		name   string
		mutate func(*provider.Response)
	}{
		{"wrong request", func(r *provider.Response) { r.RequestID = uuid.NewString() }},
		{"wrong operation", func(r *provider.Response) { r.OperationScopeID++ }},
		{"wrong authorization", func(r *provider.Response) { r.AuthContext = "another-token" }},
		{"missing profile", func(r *provider.Response) { r.ProfileRef = "" }},
		{"contradictory failure", func(r *provider.Response) { r.Error = &provider.Failure{Code: "failed"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
				response := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true, ProfileRef: "profile"}
				test.mutate(response)
				return response, nil
			}
			request, err := requestForBinding(&provider.Binding{ProviderName: "worker", OperationScopeID: 17, Scheme: "example"}, provider.PrepareProfile, nil, "", RabbitMQAuthContext{OperationID: 17})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := invokeCryptoProvider("worker", request); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
}

func TestCryptoProviderMessageLimitRejectsBeforeNativeOperation(t *testing.T) {
	previous := callCryptoProvider
	t.Cleanup(func() { callCryptoProvider = previous })
	binding := &provider.Binding{ID: uuid.NewString(), ProviderName: "worker", OperationScopeID: 17, Scheme: "example", SessionRef: "session", Namespace: "campaign", MaxMessageBytes: 4}
	calls := 0
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		calls++
		return &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true, Message: request.Message}, nil
	}
	for _, action := range []string{"encrypt", "decrypt"} {
		if _, err := cryptoProviderAct(binding, action, []byte("12345"), "", RabbitMQAuthContext{OperationID: 17}); err == nil || !strings.Contains(err.Error(), "advertised limit") {
			t.Fatalf("oversized %s was not rejected before provider work: %v", action, err)
		}
	}
	if calls != 0 {
		t.Fatalf("oversized messages reached provider: %d calls", calls)
	}
	if _, err := cryptoProviderAct(binding, "encrypt", []byte("1234"), "", RabbitMQAuthContext{OperationID: 17}); err != nil || calls != 1 {
		t.Fatalf("message at advertised limit was rejected: %v, calls=%d", err, calls)
	}
}

func TestCryptoProviderBindingLoadsCurrentAdvertisedMessageLimit(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	for _, limit := range []int{1024, 2048, 0, provider.MaxMessageBytes + 1} {
		if _, err := db.Exec(`UPDATE consuming_container SET crypto_capabilities=jsonb_build_object('max_message_bytes',$1::integer) WHERE id=1`, limit); err != nil {
			t.Fatal(err)
		}
		binding, err := loadCryptoProviderBinding(info.CryptoProviderBindingID, info.OperationID)
		if limit < 1 || limit > provider.MaxMessageBytes {
			if err == nil {
				t.Fatalf("invalid registered maximum accepted: %d", limit)
			}
		} else if err != nil || binding.MaxMessageBytes != limit {
			t.Fatalf("binding maximum did not follow current registration: binding=%+v err=%v", binding, err)
		}
	}
}
