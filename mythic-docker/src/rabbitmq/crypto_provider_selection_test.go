package rabbitmq

import (
	"testing"

	"github.com/its-a-feature/Mythic/database"
)

func TestCryptoProviderSelectionPrecedesDispatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		candidates []cryptoProviderCandidate
		want       string
		wantError  bool
	}{
		{"legacy fallback", []cryptoProviderCandidate{{Value: "aes256_hmac"}, {Value: "none"}}, "", false},
		{"external", []cryptoProviderCandidate{{BindingID: "profile-one", Value: "provider:worker:example"}}, "profile-one", false},
		{"no crypto option", []cryptoProviderCandidate{{Value: "none"}, {BindingID: "profile-one"}}, "profile-one", false},
		{"same binding", []cryptoProviderCandidate{{BindingID: "profile-one"}, {BindingID: "profile-one"}}, "profile-one", false},
		{"two profiles", []cryptoProviderCandidate{{BindingID: "profile-one"}, {BindingID: "profile-two"}}, "", true},
		{"legacy and external", []cryptoProviderCandidate{{Value: "aes256_hmac"}, {BindingID: "profile-one"}}, "", true},
		{"missing binding", []cryptoProviderCandidate{{Value: "provider:worker:example"}}, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := selectCryptoProviderBinding(test.candidates)
			if (err != nil) != test.wantError || got != test.want {
				t.Fatalf("selected=%q error=%v; want=%q error=%v", got, err, test.want, test.wantError)
			}
		})
	}
}

func TestCryptoProviderCallbackCreationChecksSelectedRoute(t *testing.T) {
	db := callbackProviderTestDB(t)
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous })
	if _, err := db.Exec(`CREATE TABLE buildparameterinstance(payload_id integer,crypto_provider_binding_id uuid);
		INSERT INTO c2profile VALUES (1,'custom',false),(2,'legacy',false);
		INSERT INTO c2profileparametersinstance(payload_id,c2_profile_id,crypto_provider_binding_id)
		VALUES (23,1,'ce42249c-2f93-4fad-b7c6-a3d688d2ba79'),(23,2,NULL);`); err != nil {
		t.Fatal(err)
	}
	for route, want := range map[string]bool{"custom": true, "legacy": false, "": true} {
		managed, err := payloadRouteUsesCryptoProvider(23, route)
		if err != nil || managed != want {
			t.Fatalf("route=%q managed=%v err=%v; want=%v", route, managed, err, want)
		}
	}
}

func TestCryptoProviderBuildRejectsAmbiguousRoute(t *testing.T) {
	db := callbackProviderTestDB(t)
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous })
	_, err := db.Exec(`CREATE TABLE buildparameterinstance(payload_id integer,value text,dec_key bytea,crypto_provider_binding_id uuid);
		CREATE TABLE c2profileparameters(id integer PRIMARY KEY,crypto_type boolean);
		INSERT INTO c2profileparameters VALUES (1,true);
		INSERT INTO payloadc2profiles VALUES (23,1);
		INSERT INTO buildparameterinstance VALUES (23,'aes256_hmac','key',NULL);
		INSERT INTO c2profileparametersinstance(payload_id,c2_profile_id,c2_profile_parameters_id,value,crypto_provider_binding_id)
		VALUES (23,1,1,'provider:worker:example','ce42249c-2f93-4fad-b7c6-a3d688d2ba79');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePayloadCryptoProviderSelections(23); err == nil {
		t.Fatal("build accepted mixed legacy and external crypto for one route")
	}
	if _, err := db.Exec(`DELETE FROM buildparameterinstance`); err != nil {
		t.Fatal(err)
	}
	if err := validatePayloadCryptoProviderSelections(23); err != nil {
		t.Fatalf("unambiguous external build rejected: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO payloadc2profiles VALUES (23,2);
		INSERT INTO c2profileparametersinstance(payload_id,c2_profile_id,c2_profile_parameters_id,value)
		VALUES (23,2,1,'aes256_hmac')`); err != nil {
		t.Fatal(err)
	}
	if err := validatePayloadCryptoProviderSelections(23); err != nil {
		t.Fatalf("independent legacy transport rejected: %v", err)
	}
}
