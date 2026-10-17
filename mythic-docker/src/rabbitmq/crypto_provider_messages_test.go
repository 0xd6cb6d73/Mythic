package rabbitmq

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/crypto/provider"
)

func TestCryptoProviderCallbackRetainsReplyAndResumesSeal(t *testing.T) {
	for _, lostSeal := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost HTTP reply", true: "lost provider seal reply"}[lostSeal], func(t *testing.T) {
			db, info := establishmentProviderTestDB(t, 36)
			info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
			info.CallbackID, info.CallbackDisplayID = 42, 7
			info.CryptoProvider.SessionRef = "native-session"
			info.CryptoProvider.Namespace = "test-namespace"
			var opens, seals, dispatches int
			var sealID string
			var sealPlaintext []byte
			callCryptoProvider = func(_ string, request provider.Request) (*provider.Response, error) {
				reply := &provider.Response{APIVersion: provider.APIVersion, RequestID: request.RequestID,
					OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true}
				switch request.Method {
				case provider.Open:
					opens++
					reply.Message = []byte(`{"action":"get_tasking"}`)
				case provider.Seal:
					seals++
					if sealID == "" {
						sealID, sealPlaintext = request.RequestID, append([]byte(nil), request.Message...)
					} else if request.RequestID != sealID || !bytes.Equal(sealPlaintext, request.Message) {
						t.Fatal("retry changed committed seal ID or exact plaintext")
					}
					if lostSeal && seals == 1 {
						return nil, errors.New("simulated lost RPC acknowledgement")
					}
					reply.Message = []byte{0, 255, 128, 42}
				default:
					t.Fatalf("unexpected crypto operation %s", request.Method)
				}
				return reply, nil
			}
			dispatch := func(_ *AgentMessageRawInput, local *cachedUUIDInfo, message map[string]interface{}, _ *recursiveProcessAgentMessageResponse) map[string]interface{} {
				dispatches++
				if local.CallbackID != 42 || local.CallbackDisplayID != 7 || message["action"] != "get_tasking" {
					t.Fatal("request-local callback metadata was lost")
				}
				return map[string]interface{}{"action": "get_tasking", "tasks": []string{"one task"}}
			}
			input := &AgentMessageRawInput{TrackingID: "first HTTP attempt"}
			body := []byte("one authenticated native record")
			auth := RabbitMQAuthContext{OperationID: info.OperationID}
			first := processCryptoProviderCallbackWithHandler(input, info, body, 36, auth, dispatch)
			if lostSeal {
				if first.Err == nil {
					t.Fatal("lost RPC acknowledgement did not remain unresolved")
				}
			} else if first.Err != nil {
				t.Fatal(first.Err)
			}
			InvalidateAllCachedUUIDInfo()
			input.TrackingID = "retry after connection loss"
			second := processCryptoProviderCallbackWithHandler(input, info, body, 36, auth, dispatch)
			if second.Err != nil || len(second.Message) == 0 || !second.OuterUuidIsCallback || second.TrackingID != input.TrackingID {
				t.Fatalf("exact callback exchange did not recover: %+v", second)
			}
			if !lostSeal && !bytes.Equal(first.Message, second.Message) {
				t.Fatal("retry did not return identical sealed response")
			}
			third := processCryptoProviderCallbackWithHandler(input, info, body, 36, auth, dispatch)
			if third.Err != nil || !bytes.Equal(second.Message, third.Message) || opens != 1 || dispatches != 1 {
				t.Fatalf("retry repeated open/application work: opens=%d dispatches=%d err=%v", opens, dispatches, third.Err)
			}
			wantSeals := 1
			if lostSeal {
				wantSeals = 2
			}
			if seals != wantSeals {
				t.Fatalf("unexpected seal calls: %d", seals)
			}
			var exchanges int
			if err := db.Get(&exchanges, `SELECT count(*) FROM crypto_provider_exchange WHERE route_uuid=$1 AND response IS NOT NULL`, info.UUID); err != nil || exchanges != 1 {
				t.Fatalf("callback reply was not retained exactly once: count=%d err=%v", exchanges, err)
			}
		})
	}
}

func TestCryptoProviderCallbackDoesNotRepeatUnresolvedDispatch(t *testing.T) {
	db, info := establishmentProviderTestDB(t, 36)
	info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
	info.CryptoProvider.SessionRef = "native-session"
	body := []byte("already dispatched native record")
	exchange, err := cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO crypto_provider_exchange(binding_id,route_uuid,input_digest,request_id,next_uuid)
		VALUES($1,$2,$3,$4,$5)`, exchange.BindingID, exchange.RouteUUID, exchange.InputDigest, exchange.RequestID, exchange.NextUUID); err != nil {
		t.Fatal(err)
	}
	callCryptoProvider = func(string, provider.Request) (*provider.Response, error) {
		t.Fatal("unresolved application dispatch allowed fresh native work")
		return nil, nil
	}
	for _, packet := range [][]byte{body, []byte("new packet on unresolved callback")} {
		result := processCryptoProviderCallback(&AgentMessageRawInput{}, info, packet, 36, RabbitMQAuthContext{OperationID: info.OperationID})
		if result.Err == nil || len(result.Message) != 0 {
			t.Fatal("unsafe application-dispatch retry was accepted")
		}
	}
}

func TestCryptoProviderCallbackClaimsSerializeAcrossBackends(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(map[bool]string{false: "distinct packet retries after dispatch", true: "duplicate packet keeps the owner"}[duplicate], func(t *testing.T) {
			db, info := establishmentProviderTestDB(t, 36)
			db.SetMaxOpenConns(4)
			info.UUID, info.UUIDType = uuid.NewString(), UUIDTYPECALLBACK
			first, err := cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, []byte("authenticated first packet"))
			if err != nil {
				t.Fatal(err)
			}
			second := first
			if !duplicate {
				second, err = cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, []byte("authenticated competing packet"))
				if err != nil {
					t.Fatal(err)
				}
			}
			type outcome struct {
				exchange cryptoProviderExchange
				claimed  bool
				err      error
			}
			start := make(chan struct{})
			outcomes := make(chan outcome, 2)
			for _, exchange := range []cryptoProviderExchange{first, second} {
				go func() {
					<-start
					claimed, err := claimCryptoProviderCallbackExchange(exchange, info.OperationID)
					outcomes <- outcome{exchange, claimed, err}
				}()
			}
			close(start)
			var winner, loser outcome
			for range 2 {
				result := <-outcomes
				if result.claimed {
					if winner.claimed || result.err != nil {
						t.Fatalf("more than one application dispatch admitted: %+v", result)
					}
					winner = result
				} else {
					loser = result
				}
			}
			if !winner.claimed || loser.exchange.RequestID == "" {
				t.Fatalf("missing winner or loser: winner=%+v loser=%+v", winner, loser)
			}
			var rows int
			if err := db.Get(&rows, `SELECT count(*) FROM crypto_provider_exchange WHERE binding_id=$1`, info.CryptoProviderBindingID); err != nil || rows != 1 {
				t.Fatalf("admitted more than one pending row: rows=%d error=%v", rows, err)
			}
			if duplicate {
				if loser.err != nil {
					t.Fatalf("duplicate failed admission: %v", loser.err)
				}
				return
			}
			if !errors.Is(loser.err, errCryptoCallbackExchangePending) {
				t.Fatalf("competing packet did not receive retryable dispatch conflict: %v", loser.err)
			}
			if _, err := db.Exec(`UPDATE crypto_provider_exchange SET response=$2 WHERE request_id=$1`, winner.exchange.RequestID, []byte("retained winning response")); err != nil {
				t.Fatal(err)
			}
			// A completed application exchange must not permanently fence the
			// provider's native session or discard its saved Open result.
			if claimed, err := claimCryptoProviderCallbackExchange(loser.exchange, info.OperationID); !claimed || err != nil {
				t.Fatalf("competing packet could not resume after saved reply: claimed=%v error=%v", claimed, err)
			}
			if err := db.Get(&rows, `SELECT count(*) FROM crypto_provider_exchange WHERE binding_id=$1`, info.CryptoProviderBindingID); err != nil || rows != 2 {
				t.Fatalf("resumed packet did not get its own dispatch: rows=%d error=%v", rows, err)
			}
		})
	}
}
