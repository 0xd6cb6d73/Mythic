package rabbitmq

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/its-a-feature/Mythic/crypto/provider"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
)

// Exercise authenticated establishment through Mythic's real recursive message
// dispatcher. Only the provider's native cryptographic boundary is replaced.
func TestCryptoProviderInitialCheckinProcessesDelegatedChildCheckin(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	if _, err := db.Exec(`
		ALTER TABLE callbackgraphedge ADD COLUMN id serial PRIMARY KEY, ADD COLUMN end_timestamp timestamptz;
		ALTER TABLE c2profile ADD COLUMN deleted boolean NOT NULL DEFAULT false;
		UPDATE c2profile SET is_p2p=false WHERE id=31;
		INSERT INTO c2profile(id,name,is_p2p) VALUES(32,'test-p2p',true);
		INSERT INTO payloadc2profiles VALUES(23,32);
		INSERT INTO c2profileparameters VALUES(62,32,true);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO c2profileparametersinstance
		(c2_profile_parameters_id,c2_profile_id,value,payload_id,crypto_provider_binding_id)
		VALUES(62,32,'provider:test-provider:test-scheme',23,$1)`, info.CryptoProviderBindingID); err != nil {
		t.Fatal(err)
	}

	// Isolate graph caches as well as the database fixture. Wait for the implicit
	// edge below before restoring these globals or releasing the fixture database.
	callbackGraph.lock.Lock()
	previousAdj, previousVersion := callbackGraph.adjMatrix, callbackGraph.version
	callbackGraph.adjMatrix = make(map[int][]cbGraphAdjMatrixEntry)
	callbackGraph.version = 0
	callbackGraph.lock.Unlock()
	c2profileNameToIdMapLock.Lock()
	previousC2Profiles := c2profileNameToIdMap
	c2profileNameToIdMap = map[string]databaseStructs.C2profile{
		"test-c2":  {ID: 31, Name: "test-c2", IsP2p: false},
		"test-p2p": {ID: 32, Name: "test-p2p", IsP2p: true},
	}
	c2profileNameToIdMapLock.Unlock()
	t.Cleanup(func() {
		callbackGraph.lock.Lock()
		callbackGraph.adjMatrix, callbackGraph.version = previousAdj, previousVersion
		callbackGraph.lock.Unlock()
		c2profileNameToIdMapLock.Lock()
		c2profileNameToIdMap = previousC2Profiles
		c2profileNameToIdMapLock.Unlock()
		BFSCache.Reset()
		callbackCheckinTargets.Reset()
	})

	notifications := 0
	notifyCryptoProviderCallbackCreated = func(databaseStructs.Callback, databaseStructs.Payload, RabbitMQAuthContext) {
		notifications++
	}
	calls := map[string]int{}
	var childCheckinFrame []byte
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		calls[request.Method]++
		response := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
			OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true}
		switch request.Method {
		case provider.BeginSession:
			response.SessionRef = string(request.Message) + "-session"
			response.Namespace, response.StateID = "test-campaign", "campaign-state"
			response.Message = []byte("authenticated handshake")
		case provider.Open:
			message := map[string]interface{}{"action": "checkin", "uuid": info.PayloadUUID, "host": "CHILD"}
			if request.SessionRef == "parent-session" {
				message["host"] = "PARENT"
				message["delegates"] = []delegateMessage{{Message: string(childCheckinFrame), SuppliedUuid: "child-local-route", C2ProfileName: "test-p2p"}}
			}
			var err error
			response.Message, err = json.Marshal(message)
			if err != nil {
				return nil, err
			}
		case provider.Seal:
			response.Message = append([]byte("sealed:"+request.SessionRef+":"), request.Message...)
		default:
			return nil, fmt.Errorf("unexpected provider operation %s", request.Method)
		}
		return response, nil
	}
	stageSession := func(name, c2 string) string {
		t.Helper()
		frame, err := providerFrame(info.PayloadUUID, []byte(name), 36)
		if err != nil {
			t.Fatal(err)
		}
		response := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &frame, C2Profile: c2})
		if response.Err != nil {
			t.Fatalf("%s registration: %v", name, response.Err)
		}
		var staging string
		if err := db.Get(&staging, `SELECT s.staging_uuid FROM staginginfo s
			JOIN crypto_provider_binding b ON b.id=s.crypto_provider_binding_id WHERE b.session_ref=$1`, name+"-session"); err != nil {
			t.Fatal(err)
		}
		return staging
	}
	parentStage := stageSession("parent", "test-c2")
	childStage := stageSession("child", "test-p2p")
	childCheckinFrame, _ = providerFrame(childStage, []byte("protected child checkin"), 36)
	parentCheckinFrame, _ := providerFrame(parentStage, []byte("protected parent checkin"), 36)

	first := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &parentCheckinFrame, C2Profile: "test-c2"})
	if first.Err != nil || first.NewCallbackUUID == "" {
		t.Fatalf("parent checkin: callback=%q err=%v", first.NewCallbackUUID, first.Err)
	}
	decodeReply := func(frame []byte, route, session string) map[string]interface{} {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(string(frame))
		prefix := []byte(route + "sealed:" + session + ":")
		if err != nil || !bytes.HasPrefix(raw, prefix) {
			t.Fatalf("reply did not preserve %s's staging envelope: %q err=%v", session, raw, err)
		}
		var message map[string]interface{}
		if err := json.Unmarshal(raw[len(prefix):], &message); err != nil {
			t.Fatal(err)
		}
		return message
	}
	parentReply := decodeReply(first.Message, parentStage, "parent-session")
	delegates, ok := parentReply["delegates"].([]interface{})
	if !ok || len(delegates) != 1 {
		t.Fatalf("initial checkin lost delegated child registration: %+v", parentReply)
	}
	delegate := delegates[0].(map[string]interface{})
	childReply := decodeReply([]byte(delegate["message"].(string)), childStage, "child-session")
	childUUID, _ := childReply["id"].(string)
	if parentReply["id"] != first.NewCallbackUUID || childUUID == "" || childUUID == first.NewCallbackUUID ||
		childReply["action"] != "checkin" || childReply["status"] != "success" ||
		delegate["new_uuid"] != childUUID || delegate["mythic_uuid"] != childUUID || delegate["c2_profile"] != "test-p2p" {
		t.Fatalf("incorrect parent/child registration replies: parent=%+v delegate=%+v child=%+v", parentReply, delegate, childReply)
	}

	// AddByAgentIds runs asynchronously in the ordinary message dispatcher.
	// Observe its committed database edge, not a sleep or only an in-memory path.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var linked bool
		err := db.Get(&linked, `SELECT EXISTS(SELECT 1 FROM callbackgraphedge e
			JOIN callback parent ON parent.id=e.source_id JOIN callback child ON child.id=e.destination_id
			WHERE parent.agent_callback_id=$1 AND child.agent_callback_id=$2 AND e.c2_profile_id=32 AND e.end_timestamp IS NULL)`,
			first.NewCallbackUUID, childUUID)
		if err != nil {
			t.Fatal(err)
		}
		if linked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("implicit P2P link did not use new parent callback %s (incoming staging route was %s)", first.NewCallbackUUID, parentStage)
		}
		time.Sleep(10 * time.Millisecond)
	}
	InvalidateAllCachedUUIDInfo()
	retry := recursiveProcessAgentMessage(&AgentMessageRawInput{Base64Message: &parentCheckinFrame, C2Profile: "test-c2"})
	if retry.Err != nil || retry.NewCallbackUUID != first.NewCallbackUUID || !bytes.Equal(first.Message, retry.Message) {
		t.Fatalf("initial checkin retry changed reply: callback=%q err=%v", retry.NewCallbackUUID, retry.Err)
	}
	if notifications != 2 || calls[provider.BeginSession] != 2 || calls[provider.Open] != 2 || calls[provider.Seal] != 2 {
		t.Fatalf("retry repeated parent or child lifecycle effects: notifications=%d provider calls=%v", notifications, calls)
	}
	for table, want := range map[string]int{"callback": 2, "staginginfo": 0, "payloadonhost": 2, "callbackgraphedge": 2, "crypto_provider_exchange": 4} {
		var count int
		if err := db.Get(&count, `SELECT count(*) FROM `+table); err != nil || count != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
}
