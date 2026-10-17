package rabbitmq

import (
	"context"
	"database/sql"
	"errors"

	"github.com/its-a-feature/Mythic/database"
)

var errCryptoCallbackExchangePending = errors.New("another callback exchange is being dispatched; retry after its response is saved")

// Admission runs after authenticated Open, without retaining a database
// connection during native RPC or application dispatch. The binding row lock
// serializes the pending-check and insertion across Mythic backends.
func claimCryptoProviderCallbackExchange(exchange cryptoProviderExchange, operationID int) (bool, error) {
	// Each query after the row lock must see the previous owner's committed
	// ledger insertion, even if the deployment uses a different DB default.
	tx, err := database.DB.BeginTxx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var bindingID string
	if err := tx.Get(&bindingID, `SELECT id FROM crypto_provider_binding
		WHERE id=$1 AND operation_id=$2 FOR UPDATE`, exchange.BindingID, operationID); err != nil {
		return false, err
	}
	var duplicate bool
	if err := tx.Get(&duplicate, `SELECT EXISTS(SELECT 1 FROM crypto_provider_exchange WHERE request_id=$1)`, exchange.RequestID); err != nil {
		return false, err
	}
	if duplicate {
		// An identical Open is idempotent; its losing duplicate never fences
		// the backend that already owns application dispatch.
		return false, nil
	}
	var pending bool
	if err := tx.Get(&pending, `SELECT EXISTS(SELECT 1 FROM crypto_provider_exchange
		WHERE binding_id=$1 AND route_uuid=$2 AND response IS NULL)`, exchange.BindingID, exchange.RouteUUID); err != nil {
		return false, err
	}
	if pending {
		// This protects application dispatch, not cryptographic state. The
		// provider retains Open's result under the same request ID for retry.
		return false, errCryptoCallbackExchangePending
	}
	claim, err := tx.Exec(`INSERT INTO crypto_provider_exchange(binding_id,route_uuid,input_digest,request_id,next_uuid)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT(binding_id,route_uuid,input_digest) DO NOTHING`,
		exchange.BindingID, exchange.RouteUUID, exchange.InputDigest, exchange.RequestID, exchange.NextUUID)
	if err != nil {
		return false, err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return claimed == 1, nil
}

// Retain a complete callback exchange before releasing its ciphertext. A client
// can then retry identical transport bytes without opening the same native
// record or dispatching its application message a second time.
func processCryptoProviderCallback(input *AgentMessageRawInput, info *cachedUUIDInfo, body []byte, width int, auth RabbitMQAuthContext) recursiveProcessAgentMessageResponse {
	return processCryptoProviderCallbackWithHandler(input, info, body, width, auth, processAgentMessageContent)
}

func processCryptoProviderCallbackWithHandler(input *AgentMessageRawInput, info *cachedUUIDInfo, body []byte, width int, auth RabbitMQAuthContext, dispatch func(*AgentMessageRawInput, *cachedUUIDInfo, map[string]interface{}, *recursiveProcessAgentMessageResponse) map[string]interface{}) recursiveProcessAgentMessageResponse {
	result := recursiveProcessAgentMessageResponse{
		OuterUuid: info.UUID, OuterUuidIsCallback: true,
		TrackingID: input.TrackingID, AgentUUIDSize: width,
	}
	if width != info.PayloadTypeMessageUUIDLength || auth.OperationID != info.OperationID {
		result.Err = errors.New("crypto callback routing metadata mismatch")
		return result
	}
	// Admission below serializes dispatch across backends. Do not hold a local
	// striped mutex across dispatch: recursive P2P packets can use the same
	// stripe, and independent outer paths can traverse sessions in reverse order.
	exchange, err := cryptoProviderExchangeForRequest(info.CryptoProviderBindingID, info.UUID, body)
	if err != nil {
		result.Err = err
		return result
	}
	if len(exchange.Response) > 0 {
		result.Message = exchange.Response
		return result
	}
	local := providerRequestCache(info, exchange.RequestID)
	var pending bool
	if err = database.DB.Get(&pending, `SELECT EXISTS(SELECT 1 FROM crypto_provider_exchange
		WHERE binding_id=$1 AND route_uuid=$2 AND response IS NULL AND request_id<>$3)`,
		exchange.BindingID, exchange.RouteUUID, exchange.RequestID); err != nil {
		result.Err = err
		return result
	}
	if pending {
		result.Err = errors.New("crypto callback has an unfinished exchange; retry the original packet or reestablish")
		return result
	}
	var exists bool
	if err = database.DB.Get(&exists, `SELECT EXISTS(SELECT 1 FROM crypto_provider_exchange WHERE request_id=$1)`, exchange.RequestID); err != nil {
		result.Err = err
		return result
	}
	var response map[string]interface{}
	if !exists {
		decrypted, openErr := DecryptMessageWithAuthContext(local, &body, auth)
		if openErr != nil {
			result.Err = openErr
			return result
		}
		// Only authenticated packets allocate a ledger row. Winning this claim
		// grants one dispatch; another backend must wait for the saved reply.
		claimed, claimErr := claimCryptoProviderCallbackExchange(exchange, info.OperationID)
		if claimErr != nil {
			result.Err = claimErr
			return result
		}
		if !claimed {
			result.Err = errors.New("crypto callback exchange is already being processed; retry the original packet")
			return result
		}
		if input.UpdateCheckinTime {
			UpdateCallbackEdgesAndCheckinTime(info)
		}
		response = dispatch(input, local, decrypted, &result)
		if result.Err != nil {
			return result
		}
	} else {
		var hasSealInput bool
		if err = database.DB.Get(&hasSealInput, `SELECT seal_input IS NOT NULL FROM crypto_provider_exchange WHERE request_id=$1`, exchange.RequestID); err != nil {
			result.Err = err
			return result
		}
		if !hasSealInput {
			// Dispatch can update tasks and drain queues. If the process died
			// before saving its response, repeating those effects is unsafe.
			result.Err = errors.New("crypto callback dispatch outcome is unresolved; reestablishment is required")
			return result
		}
	}
	result.Message, result.Err = sealCryptoProviderExchange(local, exchange.RequestID, response, auth)
	if result.Err != nil {
		return result
	}
	_, result.Err = database.DB.Exec(`UPDATE crypto_provider_exchange SET response=$2,session_binding_id=$3 WHERE request_id=$1`,
		exchange.RequestID, result.Message, info.CryptoProviderBindingID)
	if result.Err != nil {
		result.Message = nil
	}
	return result
}
