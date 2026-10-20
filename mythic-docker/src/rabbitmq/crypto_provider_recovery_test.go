package rabbitmq

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
)

func TestCryptoProviderApplicationFailureDoesNotDisableCallback(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
	info.CallbackID = 42
	info.CryptoProvider.SessionRef = "native-session"
	info.CryptoProvider.Namespace = "test-namespace"
	// An unavailable task table makes the real get_tasking handler fail after
	// this authenticated exchange has acquired dispatch ownership.
	replaceSubmittedTasksForProxyTest(t, []submittedTask{{TaskID: 99, CallbackID: 42}})
	opens, seals, dispatches := 0, 0, 0
	var replies []map[string]interface{}
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		reply := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
			OperationScopeID: info.OperationID, AuthContext: request.AuthContext, Success: true}
		switch request.Method {
		case provider.Open:
			opens++
			reply.Message = []byte(`{"action":"get_tasking","get_delegate_tasks":false,"tasking_size":1}`)
		case provider.Seal:
			seals++
			var message map[string]interface{}
			if err := json.Unmarshal(request.Message, &message); err != nil {
				t.Fatal(err)
			}
			replies = append(replies, message)
			reply.Message = append([]byte("sealed:"), request.Message...)
		default:
			t.Fatalf("unexpected method %q", request.Method)
		}
		return reply, nil
	}
	dispatch := func(_ *AgentMessageRawInput, local *cachedUUIDInfo, message map[string]interface{}, result *recursiveProcessAgentMessageResponse) map[string]interface{} {
		dispatches++
		reply, err := handleAgentMessageGetTasking(&message, local.CallbackID)
		result.Err = err
		return reply
	}
	auth := RabbitMQAuthContext{OperationID: info.OperationID}
	packet := []byte("authenticated get_tasking during database failure")
	first := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	if first.Err != nil || len(first.Message) == 0 || len(replies) != 1 || replies[0]["status"] != "error" || replies[0]["error"] != "failed to search for tasks" {
		t.Fatalf("known application failure was not returned durably: result=%+v replies=%v", first, replies)
	}
	second := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	if second.Err != nil || !bytes.Equal(first.Message, second.Message) || dispatches != 1 || opens != 1 || seals != 1 {
		t.Fatalf("application-error retry repeated work: result=%+v dispatches=%d opens=%d seals=%d", second, dispatches, opens, seals)
	}
	// Once the failed dependency no longer contributes pending work, a fresh
	// packet must run normally rather than encountering a permanent fence.
	submittedTasksAwaitingFetching.removeTask(99)
	third := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, []byte("next authenticated get_tasking"), 36, auth, dispatch)
	if third.Err != nil || dispatches != 2 || opens != 2 || seals != 2 || replies[1]["error"] != nil {
		t.Fatalf("callback remained disabled after a known application error: result=%+v replies=%v", third, replies)
	}
	var retainedPlaintexts int
	if err := db.Get(&retainedPlaintexts, `SELECT count(*) FROM crypto_provider_exchange
		WHERE dispatch_response IS NOT NULL OR seal_input IS NOT NULL`); err != nil || retainedPlaintexts != 0 {
		t.Fatalf("completed exchanges retained plaintext: count=%d error=%v", retainedPlaintexts, err)
	}
}

func TestCryptoProviderTranslationFailureResumesSavedApplicationResponse(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
	info.CryptoProvider.SessionRef = "native-session"
	info.CryptoProvider.Namespace = "test-namespace"
	opens, seals, dispatches, translations := 0, 0, 0, 0
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		reply := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
			OperationScopeID: info.OperationID, AuthContext: request.AuthContext, Success: true}
		if request.Method == provider.Open {
			opens++
			reply.Message = []byte(`{"action":"get_tasking"}`)
		} else if request.Method == provider.Seal {
			seals++
			reply.Message = append([]byte("sealed:"), request.Message...)
		} else {
			t.Fatalf("unexpected method %q", request.Method)
		}
		return reply, nil
	}
	translateCryptoProviderResponse = func(request TrMythicC2ToCustomMessageFormatMessage, _ RabbitMQAuthContext) (*TrMythicC2ToCustomMessageFormatMessageResponse, error) {
		translations++
		if translations == 1 {
			return nil, errors.New("temporary outbound translation timeout")
		}
		if request.Message["large_id"] != json.Number("9223372036854775807") || request.Message["tracking"] != "\x00" {
			t.Fatalf("saved application response changed valid JSON values: %v", request.Message)
		}
		encoded, err := json.Marshal(request.Message)
		return &TrMythicC2ToCustomMessageFormatMessageResponse{Success: true, Message: encoded}, err
	}
	dispatch := func(_ *AgentMessageRawInput, local *cachedUUIDInfo, _ map[string]interface{}, _ *recursiveProcessAgentMessageResponse) map[string]interface{} {
		dispatches++
		// Exercise the outbound translator independently of inbound format
		// conversion. Production uses the same translator name in both views.
		local.TranslationContainerName = "test-translator"
		return map[string]interface{}{"action": "get_tasking", "tasks": []string{"one task"}, "large_id": int64(math.MaxInt64), "tracking": "\x00"}
	}
	packet := []byte("authenticated record with a translated response")
	auth := RabbitMQAuthContext{OperationID: info.OperationID}
	first := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	if first.Err == nil || len(first.Message) != 0 || seals != 0 {
		t.Fatalf("translation failure released output: %+v", first)
	}
	var pending struct {
		DispatchResponse []byte `db:"dispatch_response"`
		SealInput        []byte `db:"seal_input"`
	}
	if err := db.Get(&pending, `SELECT dispatch_response,seal_input FROM crypto_provider_exchange WHERE route_uuid=$1`, info.UUID); err != nil || len(pending.DispatchResponse) == 0 || pending.SealInput != nil {
		t.Fatalf("logical response was not saved before translation: %+v error=%v", pending, err)
	}
	// An exact retry does not decrypt, so only the saved outbound work runs.
	info.TranslationContainerName = "test-translator"
	second := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	if second.Err != nil || len(second.Message) == 0 || opens != 1 || dispatches != 1 || translations != 2 || seals != 1 {
		t.Fatalf("translation recovery repeated application/native work: result=%+v opens=%d dispatches=%d translations=%d seals=%d", second, opens, dispatches, translations, seals)
	}
	third := processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	if third.Err != nil || !bytes.Equal(second.Message, third.Message) || translations != 2 || seals != 1 {
		t.Fatalf("completed translated response was not replayed exactly: %+v", third)
	}
}
