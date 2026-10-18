package rabbitmq

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCryptoProviderPayloadRejectsUnconfiguredRoute(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	if _, err := db.Exec(`INSERT INTO c2profile VALUES (32,'unconfigured',false),(33,'legacy',false);
		INSERT INTO payloadc2profiles VALUES (23,33);
		INSERT INTO c2profileparameters VALUES (62,33,true);
		INSERT INTO c2profileparametersinstance(c2_profile_parameters_id,c2_profile_id,payload_id,value)
		VALUES (62,33,23,'none')`); err != nil {
		t.Fatal(err)
	}
	if _, err := LookupEncryptionData("unconfigured", info.UUID, false); err == nil || !strings.Contains(err.Error(), "route is not configured") {
		t.Fatalf("unconfigured transport accepted the protected payload: %v", err)
	}
	legacy, err := LookupEncryptionData("legacy", info.UUID, false)
	if err != nil || legacy.CryptoProviderBindingID != "" {
		t.Fatalf("configured legacy transport rejected: binding=%q err=%v", legacy.CryptoProviderBindingID, err)
	}
	response := MythicRPCCallbackCreate(MythicRPCCallbackCreateMessage{
		PayloadUUID: info.UUID, C2ProfileName: "unconfigured",
	}, RabbitMQAuthContext{OperationID: 17})
	if response.Success || response.Error != "failed to resolve callback crypto selection" {
		t.Fatalf("public callback-create did not reject the unconfigured route: %+v", response)
	}
	var callbacks int
	if err := db.Get(&callbacks, `SELECT count(*) FROM callback`); err != nil || callbacks != 0 {
		t.Fatalf("unconfigured route created %d callbacks: %v", callbacks, err)
	}
}

func TestCryptoProviderPrefixOnlySelectsDeclaredCryptoParameters(t *testing.T) {
	for _, crypto := range []bool{false, true} {
		name := "ordinary parameter"
		if crypto {
			name = "crypto parameter with missing binding"
		}
		t.Run(name, func(t *testing.T) {
			db, _ := establishmentProviderTestDB(t, 36)
			if _, err := db.Exec(`UPDATE c2profileparametersinstance
				SET value='none',crypto_provider_binding_id=NULL;
				INSERT INTO buildparameterinstance(payload_id,build_parameter_id,value)
				VALUES (23,71,'provider:ordinary:text')`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO buildparameter(id,crypto_type) VALUES (71,$1)`, crypto); err != nil {
				t.Fatal(err)
			}
			// Use a new payload UUID so lookup cannot reuse the fixture's cached
			// provider selection after the test changes its parameters.
			payloadUUID := uuid.NewString()
			if _, err := db.Exec(`UPDATE payload SET uuid=$1 WHERE id=23`, payloadUUID); err != nil {
				t.Fatal(err)
			}
			info, err := LookupEncryptionData("test-c2", payloadUUID, false)
			if crypto {
				if err == nil || !strings.Contains(err.Error(), "binding unavailable") {
					t.Fatalf("crypto selection without a binding did not fail closed: %v", err)
				}
				return
			}
			if err != nil || info.CryptoProviderBindingID != "" {
				t.Fatalf("ordinary string changed crypto selection: binding=%q err=%v", info.CryptoProviderBindingID, err)
			}
		})
	}
}
