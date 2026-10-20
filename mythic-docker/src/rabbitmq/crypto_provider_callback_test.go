package rabbitmq

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
	"github.com/jmoiron/sqlx"
	"github.com/mitchellh/mapstructure"
)

func TestCryptoProviderCheckinRejectsAgentCryptoFields(t *testing.T) {
	for _, field := range []string{"enc_key", "dec_key", "encryption_key", "decryption_key", "crypto_type", "crypto_provider_binding_id", "ENC_KEY", "Crypto_Type"} {
		t.Run(field, func(t *testing.T) {
			incoming := map[string]interface{}{"action": "checkin", field: nil}
			_, err := handleAgentMessageCheckin(&incoming, &cachedUUIDInfo{CryptoProviderBindingID: uuid.NewString()}, "")
			if err == nil {
				t.Fatalf("accepted agent crypto field %q", field)
			}
		})
	}
	if err := validateCryptoProviderAgentFields(map[string]interface{}{"host": "host", "user": "alice"}); err != nil {
		t.Fatalf("ordinary callback metadata rejected: %v", err)
	}
}

func TestCryptoProviderCallbackClaimsAreServerOnly(t *testing.T) {
	var fromJSON MythicRPCCallbackCreateMessage
	if err := json.Unmarshal([]byte(`{"CryptoProviderBindingID":"untrusted","CryptoProviderStagingUUID":"untrusted","CryptoProviderRequestID":"untrusted","crypto_provider_binding_id":"untrusted"}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.CryptoProviderBindingID != nil || fromJSON.CryptoProviderStagingUUID != "" || fromJSON.CryptoProviderRequestID != "" {
		t.Fatal("JSON populated trusted staging claims")
	}
	var fromAgent MythicRPCCallbackCreateMessage
	if err := mapstructure.Decode(map[string]interface{}{"CryptoProviderBindingID": "untrusted", "CryptoProviderStagingUUID": "untrusted", "CryptoProviderRequestID": "untrusted"}, &fromAgent); err != nil {
		t.Fatal(err)
	}
	if fromAgent.CryptoProviderBindingID != nil || fromAgent.CryptoProviderStagingUUID != "" || fromAgent.CryptoProviderRequestID != "" {
		t.Fatal("agent decoding populated trusted staging claims")
	}
}

func TestCryptoProviderCheckinRequiresMatchingStagingPayload(t *testing.T) {
	for _, test := range []struct {
		name, routeType, trustedPayload, claimedPayload string
	}{
		{"payload route", UUIDTYPEPAYLOAD, "trusted", "trusted"},
		{"wrong payload", UUIDTYPESTAGING, "trusted", "different"},
		{"missing trusted payload", UUIDTYPESTAGING, "", "claimed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			incoming := map[string]interface{}{"action": "checkin", "uuid": test.claimedPayload}
			cache := cachedUUIDInfo{CryptoProviderBindingID: uuid.NewString(), UUIDType: test.routeType, PayloadUUID: test.trustedPayload}
			if _, err := handleAgentMessageCheckin(&incoming, &cache, ""); err == nil {
				t.Fatal("check-in accepted an invalid authenticated staging claim")
			}
		})
	}
}

func callbackProviderTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	dsn := os.Getenv("CRYPTO_PROVIDER_TEST_DSN")
	if dsn == "" {
		t.Skip("set CRYPTO_PROVIDER_TEST_DSN to run PostgreSQL provider lifecycle tests")
	}
	admin, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "provider_callback_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sqlx.Connect("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		admin.Close()
	})
	_, err = db.Exec(`
	CREATE TABLE crypto_provider_binding (id uuid PRIMARY KEY, operation_id integer NOT NULL, scheme text NOT NULL, session_ref text NOT NULL);
	CREATE TABLE callback (
		id serial PRIMARY KEY, display_id serial, agent_callback_id text NOT NULL,
		host text, pid integer, ip text, extra_info text, sleep_info text, external_ip text, integrity_level integer, os text,
		domain text, architecture text, process_name text, registered_payload_id integer,
		operation_id integer, enc_key bytea, dec_key bytea, operator_id integer, active boolean, crypto_type text,
		description text, "user" text, eventstepinstance_id integer, process_short_name text, cwd text, impersonation_context text,
		crypto_provider_binding_id uuid UNIQUE REFERENCES crypto_provider_binding(id));
	CREATE TABLE staginginfo (id serial PRIMARY KEY, staging_uuid uuid, payload_id integer, crypto_provider_binding_id uuid);
	CREATE TABLE crypto_provider_exchange (request_id uuid PRIMARY KEY, binding_id uuid, route_uuid uuid, next_uuid uuid);
	CREATE TABLE payloadcommand (payload_id integer, command_id integer, version integer);
	CREATE TABLE loadedcommands (command_id integer, version integer, callback_id integer, operator_id integer, apitokens_id integer);
	CREATE TABLE payloadc2profiles (payload_id integer, c2_profile_id integer);
	CREATE TABLE callbackc2profiles (callback_id integer, c2_profile_id integer);
	CREATE TABLE c2profile (id integer, name text, is_p2p boolean);
	CREATE TABLE c2profileparametersinstance (id serial PRIMARY KEY, c2_profile_parameters_id integer, c2_profile_id integer,
		value text, enc_key bytea, dec_key bytea, payload_id integer, callback_id integer, operation_id integer, crypto_provider_binding_id uuid);
	CREATE TABLE payloadonhost (host text, payload_id integer, operation_id integer);
	CREATE TABLE callbackgraphedge (source_id integer, destination_id integer, c2_profile_id integer, operation_id integer, metadata text, apitokens_id integer);`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func callbackProviderFixture(t *testing.T, db *sqlx.DB) (MythicRPCCallbackCreateMessage, databaseStructs.Callback, databaseStructs.Payload, RabbitMQAuthContext) {
	t.Helper()
	bindingID, stagingID, requestID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref) VALUES ($1,17,'test-provider','opaque-session')`, bindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO staginginfo (staging_uuid,payload_id,crypto_provider_binding_id) VALUES ($1,23,$2)`, stagingID, bindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO crypto_provider_exchange (request_id,binding_id,route_uuid) VALUES ($1,$2,$3)`, requestID, bindingID, stagingID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO payloadcommand VALUES (23,41,1);
		INSERT INTO payloadc2profiles VALUES (23,31);
		INSERT INTO c2profile VALUES (31,'test-c2',false);
		INSERT INTO c2profileparametersinstance (payload_id,c2_profile_parameters_id,c2_profile_id,value) VALUES (23,61,31,'provider');`); err != nil {
		t.Fatal(err)
	}
	input := MythicRPCCallbackCreateMessage{CryptoProviderBindingID: &bindingID, CryptoProviderStagingUUID: stagingID, CryptoProviderRequestID: requestID, C2ProfileName: "test-c2"}
	callback := databaseStructs.Callback{AgentCallbackID: uuid.NewString(), RegisteredPayloadID: 23, OperationID: 17, OperatorID: 7, Host: "HOST", IP: "[]", Active: true}
	return input, callback, databaseStructs.Payload{ID: 23}, RabbitMQAuthContext{OperationID: 17}
}

func TestCryptoProviderCallbackTransactionCommitsOneSession(t *testing.T) {
	db := callbackProviderTestDB(t)
	input, callback, payload, auth := callbackProviderFixture(t, db)
	tx, err := db.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	created, graph, err := createCryptoProviderCallbackTx(tx, input, auth, &callback, payload)
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if !created || !graph || !callback.CryptoProviderBindingID.Valid || callback.CryptoType != "test-provider" || callback.EncKey != nil || callback.DecKey != nil {
		t.Fatalf("unexpected managed callback: created=%v graph=%v callback=%+v", created, graph, callback)
	}
	// A second check-in blocks on the binding until this claim commits, then
	// returns the same callback even though the staging row has been consumed.
	type duplicateResult struct {
		callback databaseStructs.Callback
		created  bool
		err      error
	}
	duplicate := make(chan duplicateResult, 1)
	go func() {
		secondTx, err := db.Beginx()
		if err != nil {
			duplicate <- duplicateResult{err: err}
			return
		}
		defer secondTx.Rollback()
		secondTx.Exec(`SET LOCAL lock_timeout='5s'`)
		second := databaseStructs.Callback{AgentCallbackID: uuid.NewString()}
		created, _, err := createCryptoProviderCallbackTx(secondTx, input, auth, &second, payload)
		if err == nil {
			err = secondTx.Commit()
		}
		duplicate <- duplicateResult{callback: second, created: created, err: err}
	}()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-duplicate:
		if result.err != nil || result.created || result.callback.ID != callback.ID {
			t.Fatalf("duplicate claim returned %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent check-in did not finish")
	}
	for table, want := range map[string]int{"callback": 1, "staginginfo": 0, "loadedcommands": 1, "callbackc2profiles": 1, "callbackgraphedge": 1, "payloadonhost": 1} {
		var count int
		if err := db.Get(&count, `SELECT count(*) FROM `+table); err != nil || count != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
	var savedCallback string
	if err := db.Get(&savedCallback, `SELECT next_uuid FROM crypto_provider_exchange WHERE request_id=$1`, input.CryptoProviderRequestID); err != nil || savedCallback != callback.AgentCallbackID {
		t.Fatalf("check-in recovery route=%q, callback=%q, err=%v", savedCallback, callback.AgentCallbackID, err)
	}
}

func TestCryptoProviderCallbackTransactionRollsBackAssociations(t *testing.T) {
	db := callbackProviderTestDB(t)
	input, callback, payload, auth := callbackProviderFixture(t, db)
	if _, err := db.Exec(`ALTER TABLE callbackc2profiles ADD CONSTRAINT reject_test_callback CHECK (callback_id < 0)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := createCryptoProviderCallbackTx(tx, input, auth, &callback, payload); err == nil {
		t.Fatal("expected association insertion failure")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var callbacks, stages, commands int
	db.Get(&callbacks, `SELECT count(*) FROM callback`)
	db.Get(&stages, `SELECT count(*) FROM staginginfo`)
	db.Get(&commands, `SELECT count(*) FROM loadedcommands`)
	if callbacks != 0 || stages != 1 || commands != 0 {
		t.Fatalf("partial transaction: callbacks=%d staging=%d commands=%d", callbacks, stages, commands)
	}
}

func TestCryptoProviderCallbackRejectsWrongScopeAndPayload(t *testing.T) {
	db := callbackProviderTestDB(t)
	input, callback, payload, auth := callbackProviderFixture(t, db)
	for _, wrongScope := range []bool{true, false} {
		tx, err := db.Beginx()
		if err != nil {
			t.Fatal(err)
		}
		wrongAuth, wrongPayload := auth, payload
		if wrongScope {
			wrongAuth.OperationID++
		} else {
			wrongPayload.ID++
		}
		if _, _, err := createCryptoProviderCallbackTx(tx, input, wrongAuth, &callback, wrongPayload); err == nil {
			t.Fatalf("accepted scope mismatch=%v", wrongScope)
		}
		tx.Rollback()
	}
	var binding sql.NullString
	if err := db.Get(&binding, `SELECT crypto_provider_binding_id FROM staginginfo`); err != nil || !binding.Valid {
		t.Fatalf("invalid claims consumed staging: %v", err)
	}
}

func TestCryptoProviderCallbackRequiresMatchingRecoveryRecord(t *testing.T) {
	db := callbackProviderTestDB(t)
	input, callback, payload, auth := callbackProviderFixture(t, db)
	input.CryptoProviderRequestID = uuid.NewString()
	tx, err := db.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := createCryptoProviderCallbackTx(tx, input, auth, &callback, payload); err == nil {
		t.Fatal("accepted a check-in without its authenticated recovery record")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var callbacks, stages int
	if err := db.Get(&callbacks, `SELECT count(*) FROM callback`); err != nil {
		t.Fatal(err)
	}
	if err := db.Get(&stages, `SELECT count(*) FROM staginginfo`); err != nil {
		t.Fatal(err)
	}
	if callbacks != 0 || stages != 1 {
		t.Fatalf("incomplete recovery record consumed staging: callbacks=%d staging=%d", callbacks, stages)
	}
}
