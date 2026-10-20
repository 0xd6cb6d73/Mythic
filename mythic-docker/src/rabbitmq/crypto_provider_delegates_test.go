package rabbitmq

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	mythicCrypto "github.com/its-a-feature/Mythic/crypto"
	"github.com/its-a-feature/Mythic/crypto/provider"
)

func TestCryptoProviderDelegateCryptoCombinations(t *testing.T) {
	for _, egressManaged := range []bool{false, true} {
		for _, childManaged := range []bool{false, true} {
			t.Run(fmt.Sprintf("egress_provider_%t_child_provider_%t", egressManaged, childManaged), func(t *testing.T) {
				db, _ := establishmentProviderTestDB(t, 36)
				key := bytes.Repeat([]byte{0x42}, 32)
				makeCallback := func(id int, managed bool) *cachedUUIDInfo {
					info := &cachedUUIDInfo{UUID: uuid.NewString(), UUIDType: UUIDTYPECALLBACK,
						CallbackID: id, OperationID: 17, MythicEncrypts: true, CryptoType: "aes256_hmac",
						CallbackEncKey: &key, CallbackDecKey: &key, C2ProfileName: "test-c2", C2ProfileID: 31,
						PayloadTypeMessageFormat: "json", PayloadTypeMessageUUIDLength: 36, CallbackAllowedFromPayload: true}
					var binding interface{}
					if managed {
						info.CryptoProviderBindingID = uuid.NewString()
						info.CryptoType = "test-scheme"
						info.CryptoProvider = &provider.Binding{ID: info.CryptoProviderBindingID, OperationScopeID: 17,
							ProviderName: "test-provider", Scheme: "test-scheme", SessionRef: fmt.Sprintf("session-%d", id), Namespace: "test"}
						binding = info.CryptoProviderBindingID
						if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref) VALUES($1,17,'test-scheme',$2)`, binding, info.CryptoProvider.SessionRef); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := db.Exec(`INSERT INTO callback(id,agent_callback_id,operation_id,crypto_type,crypto_provider_binding_id) VALUES($1,$2,17,$3,$4)`, id, info.UUID, info.CryptoType, binding); err != nil {
						t.Fatal(err)
					}
					cachedUUIDInfoMap[info.UUID+"test-c2"] = info
					return info
				}
				egress, child := makeCallback(1, egressManaged), makeCallback(2, childManaged)
				var sessions []string
				callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
					if request.Method != provider.Seal || request.OperationScopeID != 17 {
						t.Fatalf("unexpected provider operation %+v", request)
					}
					sessions = append(sessions, request.SessionRef)
					return &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
						OperationScopeID: 17, AuthContext: request.AuthContext, Success: true,
						Message: append([]byte("opaque:"+request.SessionRef+":"), request.Message...)}, nil
				}
				path := []cbGraphAdjMatrixEntry{{SourceId: 1, DestinationId: 2, DestinationAgentId: child.UUID, C2ProfileName: "test-c2"}}
				inner, err := RecursivelyEncryptMessage(path, map[string]interface{}{"action": "get_tasking", "tasks": []string{"unique-task"}}, false)
				if err != nil {
					t.Fatal(err)
				}
				outer, err := EncryptMessageWithAuthContext(egress, egress.UUID, map[string]interface{}{"action": "get_tasking", "delegates": []map[string]interface{}{{"message": string(inner), "uuid": child.UUID, "c2_profile": "test-c2"}}}, true, RabbitMQAuthContext{OperationID: 17})
				if err != nil {
					t.Fatal(err)
				}
				decode := func(info *cachedUUIDInfo, frame []byte) map[string]interface{} {
					raw, err := base64.StdEncoding.DecodeString(string(frame))
					if err != nil || !bytes.HasPrefix(raw, []byte(info.UUID)) {
						t.Fatalf("invalid delegate frame %q: %v", raw, err)
					}
					body := raw[36:]
					if info.CryptoProvider != nil {
						body = bytes.TrimPrefix(body, []byte("opaque:"+info.CryptoProvider.SessionRef+":"))
					} else {
						plain, err := mythicCrypto.DecryptAES256HMAC(key, &body)
						if err != nil {
							t.Fatal(err)
						}
						body = *plain
					}
					var message map[string]interface{}
					if err := json.Unmarshal(body, &message); err != nil {
						t.Fatal(err)
					}
					return message
				}
				parentMessage := decode(egress, outer)
				delegate := parentMessage["delegates"].([]interface{})[0].(map[string]interface{})
				childMessage := decode(child, []byte(delegate["message"].(string)))
				if childMessage["tasks"].([]interface{})[0] != "unique-task" {
					t.Fatal("nested task changed")
				}
				var want []string
				if childManaged {
					want = append(want, "session-2")
				}
				if egressManaged {
					want = append(want, "session-1")
				}
				if fmt.Sprint(sessions) != fmt.Sprint(want) {
					t.Fatalf("provider seals=%v, want=%v", sessions, want)
				}
			})
		}
	}
}

func TestCryptoProviderRecursiveCallbacksRetainBothReplies(t *testing.T) {
	db, parent := establishmentProviderTestDB(t, 36)
	parent.UUID, parent.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
	parent.CryptoProvider.SessionRef = "parent-session"
	parent.CryptoProvider.Namespace = "test"
	stripe := func(id string) byte { sum := sha256.Sum256([]byte(id)); return sum[0] % 64 }
	childBinding := uuid.NewString()
	for stripe(childBinding) != stripe(parent.CryptoProviderBindingID) {
		childBinding = uuid.NewString()
	}
	if _, err := db.Exec(`INSERT INTO crypto_provider_binding(id,operation_id,scheme,session_ref) VALUES($1,17,'test-scheme','child-session')`, childBinding); err != nil {
		t.Fatal(err)
	}
	child := providerRequestCache(parent, "")
	child.UUID, child.CryptoProviderBindingID = uuid.NewString(), childBinding
	child.CryptoProvider = &provider.Binding{ID: childBinding, ProviderName: "test-provider", OperationScopeID: 17, Scheme: "test-scheme", Namespace: "test", SessionRef: "child-session"}
	opens, seals, dispatches := 0, 0, 0
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		reply := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID, OperationScopeID: 17, AuthContext: request.AuthContext, Success: true}
		switch request.Method {
		case provider.Open:
			opens++
			reply.Message = []byte(`{"action":"get_tasking"}`)
		case provider.Seal:
			seals++
			reply.Message = append([]byte("sealed:"), request.Message...)
		default:
			t.Fatalf("unexpected provider operation %s", request.Method)
		}
		return reply, nil
	}
	auth := RabbitMQAuthContext{OperationID: 17}
	childDispatch := func(_ *AgentMessageRawInput, _ *cachedUUIDInfo, _ map[string]interface{}, _ *recursiveProcessAgentMessageResponse) map[string]interface{} {
		dispatches++
		return map[string]interface{}{"action": "get_tasking", "tasks": []string{"one-child-task"}}
	}
	parentDispatch := func(_ *AgentMessageRawInput, _ *cachedUUIDInfo, _ map[string]interface{}, result *recursiveProcessAgentMessageResponse) map[string]interface{} {
		dispatches++
		inner := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, child, []byte("child-record"), 36, auth, childDispatch)
		if inner.Err != nil {
			result.Err = inner.Err
			return nil
		}
		return map[string]interface{}{"action": "get_tasking", "delegates": []map[string]interface{}{{"message": string(inner.Message)}}}
	}
	first := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, parent, []byte("parent-record"), 36, auth, parentDispatch)
	second := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, parent, []byte("parent-record"), 36, auth, parentDispatch)
	if first.Err != nil || second.Err != nil || opens != 2 || seals != 2 || dispatches != 2 || !bytes.Equal(first.Message, second.Message) {
		t.Fatalf("nested callback replay changed work: opens=%d seals=%d dispatches=%d first=%v second=%v", opens, seals, dispatches, first.Err, second.Err)
	}
	var retained int
	if err := db.Get(&retained, `SELECT count(*) FROM crypto_provider_exchange WHERE response IS NOT NULL`); err != nil || retained != 2 {
		t.Fatalf("retained replies=%d err=%v", retained, err)
	}
}
