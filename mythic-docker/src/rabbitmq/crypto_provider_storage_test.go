package rabbitmq

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	amqp "github.com/rabbitmq/amqp091-go"
)

func storageWire(t *testing.T, name string, method string, input interface{}) (amqp.Delivery, cryptoProviderStorageRequest) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := cryptoProviderStorageRequest{APIVersion: provider.APIVersion, RequestID: uuid.NewString(), ProviderName: name, Method: method, Input: raw}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	token, err := GenerateRabbitMQAuthContextToken(RabbitMQAuthContext{ContainerName: name, OperationID: 17})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { InvalidateRabbitMQAuthContextToken(token) })
	return amqp.Delivery{Body: body, Headers: amqp.Table{MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER: token}}, req
}

func storageReply(t *testing.T, wire interface{}, req cryptoProviderStorageRequest) cryptoProviderStorageResponse {
	t.Helper()
	response, ok := wire.(cryptoProviderStorageResponse)
	if !ok {
		t.Fatalf("unexpected storage response: %T", wire)
	}
	if response.RequestID != req.RequestID || response.ProviderName != req.ProviderName || response.APIVersion != provider.APIVersion {
		t.Fatal("storage response correlation mismatch")
	}
	return response
}

func TestCryptoProviderStorageRejectsInvalidContextBeforeDatabase(t *testing.T) {
	previous := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = previous })
	for _, mutation := range []string{"missing header", "unknown token", "expired token", "operator context", "wrong provider", "missing operation", "malformed body", "wrong version", "invalid request ID"} {
		t.Run(mutation, func(t *testing.T) {
			message, req := storageWire(t, "worker-a", "load", provider.StateKey{Namespace: "sessions", StateID: "one"})
			switch mutation {
			case "missing header":
				message.Headers = nil
			case "unknown token":
				message.Headers[MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER] = "mctx_unknown"
			case "expired token":
				InvalidateRabbitMQAuthContextToken(message.Headers[MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER].(string))
			case "operator context", "wrong provider", "missing operation":
				auth := RabbitMQAuthContext{OperationID: 17, ContainerName: "worker-a"}
				if mutation == "operator context" {
					auth.ContainerName = ""
				} else if mutation == "wrong provider" {
					auth.ContainerName = "worker-b"
				} else {
					auth.OperationID = 0
				}
				token, err := GenerateRabbitMQAuthContextToken(auth)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { InvalidateRabbitMQAuthContextToken(token) })
				message.Headers[MYTHIC_RABBITMQ_AUTH_CONTEXT_HEADER] = token
			case "malformed body":
				message.Body = []byte(`{`)
			case "wrong version":
				req.APIVersion++
				message.Body, _ = json.Marshal(req)
			case "invalid request ID":
				req.RequestID = "bad"
				message.Body, _ = json.Marshal(req)
			}
			if _, ok := processCryptoProviderStorage(message).(cryptoProviderStorageResponse); ok {
				t.Fatal("invalid authorization/request reached storage")
			}
		})
	}
}

func TestCryptoProviderStorageAuthenticatedIsolation(t *testing.T) {
	db := callbackProviderTestDB(t)
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous })
	_, err := db.Exec(`CREATE TABLE consuming_container(id integer PRIMARY KEY,name text,type text,deleted boolean);
		INSERT INTO consuming_container VALUES (1,'worker-a','crypto',false),(2,'worker-b','crypto',false),(3,'payload','payload',false),(4,'deleted-worker','crypto',true);
		CREATE TABLE crypto_provider_state(provider_id integer,namespace text,state_id text,state_blob bytea,provider_json jsonb,
			revision bigint,owner_epoch bigint,updated_at timestamptz DEFAULT now(),PRIMARY KEY(provider_id,namespace,state_id));`)
	if err != nil {
		t.Fatal(err)
	}
	stateKey := provider.StateKey{Namespace: "sessions", StateID: "same-name"}
	create, req := storageWire(t, "worker-a", "create", provider.CreateStateRequest{StateKey: stateKey, StateBlob: []byte{0, 255, 128}, ProviderJSON: json.RawMessage(`{"version":9}`)})
	response := storageReply(t, processCryptoProviderStorage(create), req)
	if !response.Success || response.Error != nil {
		t.Fatalf("create failed: %+v", response)
	}
	// A context issued to another registered provider cannot read this row.
	load, req := storageWire(t, "worker-b", "load", stateKey)
	response = storageReply(t, processCryptoProviderStorage(load), req)
	if response.Success || response.Error == nil || response.Error.Code != "not_found" {
		t.Fatalf("cross-provider read returned %+v", response)
	}
	// Merely naming the first provider cannot change the token's bound identity.
	forged := req
	forged.ProviderName = "worker-a"
	load.Body, _ = json.Marshal(forged)
	if _, ok := processCryptoProviderStorage(load).(cryptoProviderStorageResponse); ok {
		t.Fatal("storage trusted provider body name over authorization context")
	}
	for _, name := range []string{"unknown", "payload", "deleted-worker"} {
		t.Run(name, func(t *testing.T) {
			load, req := storageWire(t, name, "load", stateKey)
			response := storageReply(t, processCryptoProviderStorage(load), req)
			if response.Success || response.Error == nil || response.Error.Code != "unauthorized" {
				t.Fatalf("unregistered provider received storage access: %+v", response)
			}
		})
	}
}
