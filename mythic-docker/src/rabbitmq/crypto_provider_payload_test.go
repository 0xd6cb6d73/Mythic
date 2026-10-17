package rabbitmq

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
)

func TestPayloadSupportedCryptoSchemesSync(t *testing.T) {
	for _, test := range []struct {
		name, definition, stored string
		invalid                  bool
	}{
		{"legacy omission", `{}`, `[]`, false},
		{"empty", `{"supported_crypto_schemes":[]}`, `[]`, false},
		{"null", `{"supported_crypto_schemes":null}`, `[]`, false},
		{"external", `{"supported_crypto_schemes":["example","Other_1.2"]}`, `["example","Other_1.2"]`, false},
		{"duplicate", `{"supported_crypto_schemes":["example","example"]}`, "", true},
		{"qualified", `{"supported_crypto_schemes":["provider:worker:example"]}`, "", true},
		{"wrong type", `{"supported_crypto_schemes":[3]}`, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var declaration PayloadType
			err := json.Unmarshal([]byte(test.definition), &declaration)
			var stored databaseStructs.MythicJSONArray
			if err == nil {
				stored, err = supportedCryptoSchemesForSync(declaration)
			}
			if (err != nil) != test.invalid || (err == nil && string(stored) != test.stored) {
				t.Fatalf("stored=%s err=%v; want=%s invalid=%v", stored, err, test.stored, test.invalid)
			}
		})
	}
}

func TestPayloadSupportedCryptoSchemesSyncRejectsBeforeDatabase(t *testing.T) {
	previous := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = previous })
	err := payloadTypeSync(PayloadTypeSyncMessage{
		ContainerVersion: "v1.5.0",
		PayloadType: PayloadType{
			Name:                   "example-agent",
			SupportedCryptoSchemes: []string{"example", "example"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "supported_crypto_schemes") {
		t.Fatalf("invalid declaration reached database lookup: %v", err)
	}
}

func TestPayloadSupportedCryptoSchemesResyncPersistsAndClears(t *testing.T) {
	db := callbackProviderTestDB(t)
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous })
	t.Chdir(t.TempDir())
	if err := os.Mkdir(filepath.Join(".", "static"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`
		CREATE TABLE payloadtype (
			id integer PRIMARY KEY, name text NOT NULL, author text NOT NULL DEFAULT '', container_running boolean NOT NULL DEFAULT false,
			file_extension text NOT NULL DEFAULT '', mythic_encrypts boolean NOT NULL DEFAULT true, note text NOT NULL DEFAULT '',
			supported_os jsonb NOT NULL DEFAULT '[]', supports_dynamic_loading boolean NOT NULL DEFAULT false,
			wrapper boolean NOT NULL DEFAULT false, agent_type text NOT NULL DEFAULT 'agent', message_format text NOT NULL DEFAULT 'json',
			command_augment_supported_agents jsonb NOT NULL DEFAULT '[]', message_uuid_length integer NOT NULL DEFAULT 36,
			use_display_params_for_cli_history boolean NOT NULL DEFAULT false, c2_parameter_deviations jsonb NOT NULL DEFAULT '{}',
			command_help_function text NOT NULL DEFAULT '', supports_multiple_c2_in_build boolean NOT NULL DEFAULT false,
			supports_multiple_c2_instances_in_build boolean NOT NULL DEFAULT false, supported_c2 jsonb NOT NULL DEFAULT '[]',
			semver text NOT NULL DEFAULT '', wrapper_payload_requirements jsonb NOT NULL DEFAULT '[]',
			supported_translation_container text NOT NULL DEFAULT '', supported_crypto_schemes jsonb NOT NULL DEFAULT '[]',
			deleted boolean NOT NULL DEFAULT false);
		INSERT INTO payloadtype(id,name) VALUES (7,'example-agent');
		CREATE TABLE payloadtypec2profile (id integer, payload_type_id integer, c2_profile_id integer);
		CREATE TABLE command (id integer, payload_type_id integer);
		CREATE TABLE buildparameter (id integer, payload_type_id integer);
		CREATE TABLE payload_build_step (id integer, payloadtype_id integer, payload_id integer);`)
	if err != nil {
		t.Fatal(err)
	}
	declaration := PayloadTypeSyncMessage{
		ContainerVersion: "v1.5.0",
		ForcedSync:       true,
		PayloadType: PayloadType{
			Name:                   "example-agent",
			SupportedCryptoSchemes: []string{"example"},
		},
	}
	assertStored := func(want string) {
		t.Helper()
		var got string
		if err := db.Get(&got, `SELECT supported_crypto_schemes::text FROM payloadtype WHERE id=7`); err != nil || got != want {
			t.Fatalf("stored schemes=%q err=%v; want=%q", got, err, want)
		}
	}
	if err := payloadTypeSync(declaration); err != nil {
		t.Fatal(err)
	}
	assertStored(`["example"]`)
	declaration.PayloadType.SupportedCryptoSchemes = []string{"example", "example"}
	if err := payloadTypeSync(declaration); err == nil {
		t.Fatal("invalid resync was accepted")
	}
	assertStored(`["example"]`)
	declaration.PayloadType.SupportedCryptoSchemes = nil
	if err := payloadTypeSync(declaration); err != nil {
		t.Fatal(err)
	}
	assertStored(`[]`)
	declaration.PayloadType.SupportedCryptoSchemes = []string{"replacement"}
	if err := payloadTypeSync(declaration); err != nil {
		t.Fatal(err)
	}
	assertStored(`["replacement"]`)
	declaration.PayloadType.SupportedCryptoSchemes = []string{}
	if err := payloadTypeSync(declaration); err != nil {
		t.Fatal(err)
	}
	assertStored(`[]`)
}

func TestPayloadCryptoSchemeCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, declared, selection string
		invalid                   bool
	}{
		{"legacy AES without declaration", "", "aes256_hmac", false},
		{"legacy none without declaration", "", "none", false},
		{"legacy translation without declaration", "", "custom-translation", false},
		{"legacy ignores external declaration", `["example"]`, "aes256_hmac", false},
		{"omitted", "", "provider:worker:example", true},
		{"empty", `[]`, "provider:worker:example", true},
		{"null", `null`, "provider:worker:example", true},
		{"supported", `["example"]`, "provider:worker:example", false},
		{"other worker same scheme", `["example"]`, "provider:other-worker:example", false},
		{"wrong scheme", `["other"]`, "provider:worker:example", true},
		{"case mismatch", `["Example"]`, "provider:worker:example", true},
		{"malformed selection", `["example"]`, "provider:worker", true},
		{"invalid stored declaration", `["example",3]`, "provider:worker:example", true},
		{"duplicate stored declaration", `["example","example"]`, "provider:worker:example", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			payloadType := databaseStructs.Payloadtype{Name: "example-agent", SupportedCryptoSchemes: databaseStructs.MythicJSONArray(test.declared)}
			if err := validatePayloadCryptoScheme(payloadType, test.selection); (err != nil) != test.invalid {
				t.Fatalf("compatibility=%v; invalid=%v", err, test.invalid)
			}
		})
	}
}

func TestPayloadCryptoCompatibilityPrecedesProviderPreparation(t *testing.T) {
	previousDB, previousCall := database.DB, callCryptoProvider
	database.DB = nil
	called := false
	callCryptoProvider = func(string, provider.Request) (*provider.Response, error) {
		called = true
		return nil, errors.New("unsupported payload reached provider")
	}
	t.Cleanup(func() { database.DB, callCryptoProvider = previousDB, previousCall })
	_, err := prepareCryptoProviderKeysForPayload(databaseStructs.Payloadtype{Name: "legacy-agent"}, "provider:worker:example", 17, RabbitMQAuthContext{OperationID: 17})
	if err == nil || !strings.Contains(err.Error(), "not supported by payload type") || called {
		t.Fatalf("provider preparation happened before compatibility: called=%v err=%v", called, err)
	}
	if _, err := prepareCryptoProviderKeysForPayload(databaseStructs.Payloadtype{Name: "legacy-agent"}, "none", 17, RabbitMQAuthContext{}); err != nil {
		t.Fatalf("legacy none selection changed: %v", err)
	}
}

func TestPayloadCryptoCompatibilityBuildAndC2Paths(t *testing.T) {
	db := callbackProviderTestDB(t)
	previousDB, previousCall := database.DB, callCryptoProvider
	database.DB = db
	called := false
	callCryptoProvider = func(string, provider.Request) (*provider.Response, error) {
		called = true
		return nil, errors.New("unsupported payload reached provider")
	}
	t.Cleanup(func() { database.DB, callCryptoProvider = previousDB, previousCall })
	_, err := db.Exec(`
		CREATE TABLE payloadtype (id integer PRIMARY KEY, c2_parameter_deviations jsonb NOT NULL DEFAULT '{}');
		INSERT INTO payloadtype VALUES (7,'{}');
		CREATE TABLE buildparameter (id integer PRIMARY KEY, name text, parameter_type text, crypto_type boolean,
			payload_type_id integer, deleted boolean DEFAULT false);
		INSERT INTO buildparameter VALUES (1,'encryption','ChooseOne',true,7,false);
		CREATE TABLE c2profileparameters (id integer PRIMARY KEY, name text, parameter_type text, crypto_type boolean,
			c2_profile_id integer, deleted boolean DEFAULT false);
		INSERT INTO c2profileparameters VALUES (1,'encryption','ChooseOne',true,1,false);
		ALTER TABLE c2profile ADD COLUMN deleted boolean DEFAULT false;
		INSERT INTO c2profile(id,name,is_p2p) VALUES (1,'test-transport',false);`)
	if err != nil {
		t.Fatal(err)
	}
	payload := databaseStructs.Payload{ID: 23, PayloadTypeID: 7, OperationID: 17,
		Payloadtype: databaseStructs.Payloadtype{Name: "legacy-agent"}}
	buildParameters := []PayloadConfigurationBuildParameter{{Name: "encryption", Value: "provider:worker:example"}}
	c2Profiles := []PayloadConfigurationC2Profile{{Name: "test-transport", Parameters: map[string]interface{}{"encryption": "provider:worker:example"}}}
	_, buildErr := associateBuildParametersWithPayload(payload, &buildParameters, RabbitMQAuthContext{OperationID: 17})
	_, c2Err := associateC2ProfilesWithPayload(payload, &c2Profiles, RabbitMQAuthContext{OperationID: 17})
	for name, err := range map[string]error{"build": buildErr, "C2": c2Err} {
		if err == nil || !strings.Contains(err.Error(), "not supported by payload type") {
			t.Fatalf("%s path did not enforce payload compatibility: %v", name, err)
		}
	}
	if called {
		t.Fatal("unsupported payload created provider state")
	}
}
