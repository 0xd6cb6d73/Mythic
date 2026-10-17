package rabbitmq

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
	"github.com/its-a-feature/Mythic/database"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
)

func TestCryptoProviderBuildProjection(t *testing.T) {
	key := []byte("existing-key")
	legacy, err := GetInterfaceValueForContainer(BUILD_PARAMETER_TYPE_CHOOSE_ONE, "aes256_hmac", &key, &key, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyJSON) != `{"dec_key":"ZXhpc3Rpbmcta2V5","enc_key":"ZXhpc3Rpbmcta2V5","value":"aes256_hmac"}` {
		t.Fatalf("legacy crypto projection changed: %s", legacyJSON)
	}
	opaque := []byte{0, 255, 1, 128}
	config := encodeCryptoProviderAgentConfig(opaque)
	external, err := GetInterfaceValueForContainer(BUILD_PARAMETER_TYPE_CHOOSE_ONE, "provider:sample:test", nil, nil, true, config)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(external)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["provider_config"]) != string(config) {
		t.Fatalf("provider configuration is not preserved: %s", encoded)
	}
	var recovered []byte
	if err := json.Unmarshal(decoded["provider_config"], &recovered); err != nil || string(recovered) != string(opaque) {
		t.Fatalf("opaque provider configuration did not round trip: %x, %v", recovered, err)
	}
	if encodeCryptoProviderAgentConfig(nil) != nil {
		t.Fatal("absent configuration must remain absent")
	}
	if _, ok := decoded["provider_binding_id"]; ok {
		t.Fatal("internal binding leaked into builder configuration")
	}
	if _, err := GetInterfaceValueForContainer(BUILD_PARAMETER_TYPE_CHOOSE_ONE, "provider:sample:test", nil, nil, true, json.RawMessage(`{"broken"`)); err == nil {
		t.Fatal("invalid provider build JSON accepted")
	}
	for _, parameterType := range []string{BUILD_PARAMETER_TYPE_STRING, BUILD_PARAMETER_TYPE_CHOOSE_ONE_CUSTOM} {
		projected, err := GetInterfaceValueForContainer(parameterType, "provider:sample:test", nil, nil, true, config)
		if err != nil {
			t.Fatal(err)
		}
		if projectedMap, ok := projected.(map[string]interface{}); !ok || projectedMap["provider_config"] == nil {
			t.Fatalf("%s crypto parameter lost provider configuration", parameterType)
		}
	}
}

func TestCryptoCapabilitiesSyncValidation(t *testing.T) {
	valid := provider.Capabilities{APIVersion: provider.APIVersion, Schemes: []string{"example"}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: 1024, ResultRetentionSeconds: 3600}
	for _, test := range []struct {
		name       string
		definition ConsumingContainerDefinition
		wantError  bool
	}{
		{"legacy", ConsumingContainerDefinition{Type: "webhook"}, false},
		{"crypto", ConsumingContainerDefinition{Type: "crypto", CryptoCapabilities: &valid}, false},
		{"missing", ConsumingContainerDefinition{Type: "crypto"}, true},
		{"wrong type", ConsumingContainerDefinition{Type: "webhook", CryptoCapabilities: &valid}, true},
		{"invalid", ConsumingContainerDefinition{Type: "crypto", CryptoCapabilities: &provider.Capabilities{}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := cryptoCapabilitiesForSync(test.definition)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
			if err == nil && !json.Valid(encoded) {
				t.Fatalf("invalid stored capabilities: %s", encoded)
			}
		})
	}
}

func TestCryptoProviderBuildConfigurationReload(t *testing.T) {
	db := callbackProviderTestDB(t)
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previousDB })
	_, err := db.Exec(`
		ALTER TABLE crypto_provider_binding ADD COLUMN agent_config bytea, ADD COLUMN enc_key bytea, ADD COLUMN dec_key bytea;
		CREATE TABLE buildparameter (id integer PRIMARY KEY, name text, parameter_type text, crypto_type boolean);
		CREATE TABLE buildparameterinstance (id serial PRIMARY KEY, payload_id integer, build_parameter_id integer,
			value text, enc_key bytea, dec_key bytea, crypto_provider_binding_id uuid);
		CREATE TABLE c2profileparameters (id integer PRIMARY KEY, name text, parameter_type text, crypto_type boolean);
		INSERT INTO buildparameter VALUES (1,'encryption','ChooseOne',true);
		INSERT INTO c2profileparameters VALUES (1,'encryption','ChooseOne',true);
		INSERT INTO c2profile VALUES (1,'test-transport',false);`)
	if err != nil {
		t.Fatal(err)
	}
	bindingID := uuid.NewString()
	opaque := []byte{0, 255, 1, 128}
	if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref,agent_config) VALUES ($1,17,'example','',$2)`, bindingID, opaque); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO buildparameterinstance(payload_id,build_parameter_id,value,crypto_provider_binding_id)
		VALUES (23,1,'provider:worker:example',$1)`, bindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO c2profileparametersinstance(payload_id,callback_id,c2_profile_id,c2_profile_parameters_id,value,crypto_provider_binding_id)
		VALUES (23,42,1,1,'provider:worker:example',$1)`, bindingID); err != nil {
		t.Fatal(err)
	}
	assertProjection := func(name string, value interface{}) {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Value  string `json:"value"`
			Config []byte `json:"provider_config"`
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil || string(decoded.Config) != string(opaque) || decoded.Value != "provider:worker:example" {
			t.Fatalf("%s dropped provider build configuration: %s, %v", name, encoded, err)
		}
	}
	build := GetBuildParameterInformation(23)
	if build == nil || len(*build) != 1 {
		t.Fatal("missing build parameter information")
	}
	assertProjection("build", (*build)[0].Value)
	for name, profiles := range map[string]*[]PayloadConfigurationC2Profile{
		"payload":  GetPayloadC2ProfileInformation(databaseStructs.Payload{ID: 23}),
		"callback": GetCallbackC2ProfileInformation(databaseStructs.Callback{ID: 42}),
	} {
		if profiles == nil || len(*profiles) != 1 {
			t.Fatalf("missing %s C2 configuration", name)
		}
		assertProjection(name, (*profiles)[0].Parameters["encryption"])
	}
	tasking := GetTaskMessageCallbackC2ProfileInformation(42)
	if len(tasking) != 1 {
		t.Fatal("missing tasking C2 configuration")
	}
	assertProjection("tasking", tasking[0].Parameters["encryption"])
}
