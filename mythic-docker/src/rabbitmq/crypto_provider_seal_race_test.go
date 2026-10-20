package rabbitmq

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
)

func TestCryptoProviderConcurrentTranslationCannotResurrectCompletedPlaintext(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	db.SetMaxOpenConns(4)
	info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
	info.CryptoProvider.SessionRef = "native-session"
	info.CryptoProvider.Namespace = "campaign"
	var opens, seals, dispatches, translations atomic.Int32
	callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
		reply := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
			OperationScopeID: info.OperationID, AuthContext: request.AuthContext, Success: true}
		switch request.Method {
		case provider.Open:
			opens.Add(1)
			reply.Message = []byte(`{"action":"get_tasking"}`)
		case provider.Seal:
			seals.Add(1)
			reply.Message = append([]byte("sealed:"), request.Message...)
		default:
			return nil, errors.New("unexpected provider operation")
		}
		return reply, nil
	}

	slowStarted, releaseSlow := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSlow) }) }
	translateCryptoProviderResponse = func(TrMythicC2ToCustomMessageFormatMessage, RabbitMQAuthContext) (*TrMythicC2ToCustomMessageFormatMessageResponse, error) {
		switch translations.Add(1) {
		case 1:
			return nil, errors.New("temporary translation failure before any seal")
		case 2:
			close(slowStarted)
			select {
			case <-releaseSlow:
				// A translator need not produce byte-identical output for repeated
				// calls. Only the winning persisted plaintext may reach Seal.
				return &TrMythicC2ToCustomMessageFormatMessageResponse{Success: true, Message: []byte("slow translated output")}, nil
			case <-time.After(10 * time.Second):
				return nil, errors.New("timed out waiting to release slow translation")
			}
		case 3:
			return &TrMythicC2ToCustomMessageFormatMessageResponse{Success: true, Message: []byte("fast translated output")}, nil
		default:
			return nil, errors.New("unexpected repeated translation")
		}
	}
	dispatch := func(_ *AgentMessageRawInput, local *cachedUUIDInfo, _ map[string]interface{}, _ *recursiveProcessAgentMessageResponse) map[string]interface{} {
		dispatches.Add(1)
		// Inbound Open uses the ordinary JSON parser; only the outgoing reply
		// needs the local translation seam exercised by this regression.
		local.TranslationContainerName = "test-translator"
		return map[string]interface{}{"action": "get_tasking", "tasks": []string{"one task"}}
	}
	packet := []byte("authenticated packet with concurrent translated retries")
	auth := RabbitMQAuthContext{OperationID: info.OperationID}
	process := func() recursiveProcessAgentMessageResponse {
		return processCryptoProviderCallbackWithHandler(&AgentMessageRawInput{}, info, packet, 36, auth, dispatch)
	}
	if first := process(); first.Err == nil || len(first.Message) != 0 || seals.Load() != 0 {
		t.Fatalf("initial translation failure released an encrypted response: %+v", first)
	}
	var savedLogicalResponse bool
	if err := db.Get(&savedLogicalResponse, `SELECT dispatch_response IS NOT NULL AND seal_input IS NULL AND response IS NULL
		FROM crypto_provider_exchange WHERE route_uuid=$1`, info.UUID); err != nil || !savedLogicalResponse {
		t.Fatalf("translation failure did not retain the application outcome: saved=%t err=%v", savedLogicalResponse, err)
	}
	// Exact retries skip Open and dispatch and resume only the saved response.
	info.TranslationContainerName = "test-translator"
	slowResult := make(chan recursiveProcessAgentMessageResponse, 1)
	slowFinished := make(chan struct{})
	go func() {
		defer close(slowFinished)
		slowResult <- process()
	}()
	t.Cleanup(func() {
		release()
		select {
		case <-slowFinished:
		case <-time.After(10 * time.Second):
			t.Error("slow retry did not terminate")
		}
	})
	select {
	case <-slowStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("slow retry did not reach outbound translation")
	}
	fastResult := make(chan recursiveProcessAgentMessageResponse, 1)
	go func() { fastResult <- process() }()
	var fast recursiveProcessAgentMessageResponse
	select {
	case fast = <-fastResult:
	case <-time.After(10 * time.Second):
		t.Fatal("fast retry did not finish while slow translation was blocked")
	}
	if fast.Err != nil || len(fast.Message) == 0 {
		t.Fatalf("fast retry did not complete the saved exchange: %+v", fast)
	}
	assertCompleted := func() {
		t.Helper()
		var saved struct {
			Response         []byte `db:"response"`
			DispatchResponse []byte `db:"dispatch_response"`
			SealInput        []byte `db:"seal_input"`
		}
		if err := db.Get(&saved, `SELECT response,dispatch_response,seal_input FROM crypto_provider_exchange WHERE route_uuid=$1`, info.UUID); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(saved.Response, fast.Message) || saved.DispatchResponse != nil || saved.SealInput != nil {
			t.Fatalf("completed exchange retained or recreated plaintext: %+v", saved)
		}
	}
	assertCompleted()
	release()
	select {
	case slow := <-slowResult:
		if slow.Err != nil || !bytes.Equal(slow.Message, fast.Message) {
			t.Fatalf("slow retry did not replay the completed ciphertext: %+v", slow)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("slow retry did not resume after its translator returned")
	}
	assertCompleted()
	if opens.Load() != 1 || dispatches.Load() != 1 || seals.Load() != 1 || translations.Load() != 3 {
		t.Fatalf("concurrent retry repeated work: opens=%d dispatches=%d seals=%d translations=%d", opens.Load(), dispatches.Load(), seals.Load(), translations.Load())
	}
}
