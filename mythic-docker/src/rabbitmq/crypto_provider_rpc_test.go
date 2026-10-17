package rabbitmq

import (
	"errors"
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
