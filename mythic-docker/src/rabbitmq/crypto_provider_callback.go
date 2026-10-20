package rabbitmq

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/its-a-feature/Mythic/database"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
	"github.com/jmoiron/sqlx"
)

// The managed path invokes this only after its transaction commits. Package
// integration tests can observe notifications without starting broker workers.
var notifyCryptoProviderCallbackCreated = func(callback databaseStructs.Callback, payload databaseStructs.Payload, authContext RabbitMQAuthContext) {
	notifyCallbackCreated(callback, payload, authContext)
	triggerCallbackCreatedEvents(callback, authContext)
}

// Provider bindings are authenticated server state. An agent may update its
// callback information, but cannot replace the session through application JSON.
func validateCryptoProviderAgentFields(incoming map[string]interface{}) error {
	for field := range incoming {
		switch strings.ToLower(field) {
		case "enc_key", "dec_key", "encryption_key", "decryption_key", "crypto_type", "crypto_provider_binding_id":
			return fmt.Errorf("provider sessions cannot replace %s", field)
		}
	}
	return nil
}

func callbackCreationResult(callback databaseStructs.Callback) MythicRPCCallbackCreateMessageResponse {
	return MythicRPCCallbackCreateMessageResponse{
		Success: true, AgentCallbackID: callback.AgentCallbackID,
		CallbackID: callback.ID, CallbackDisplayID: callback.DisplayID,
	}
}

func createCryptoProviderCallback(input MythicRPCCallbackCreateMessage, authContext RabbitMQAuthContext, callback databaseStructs.Callback, payload databaseStructs.Payload) MythicRPCCallbackCreateMessageResponse {
	result := MythicRPCCallbackCreateMessageResponse{}
	if input.CryptoProviderBindingID == nil || input.CryptoProviderStagingUUID == "" || input.CryptoProviderRequestID == "" {
		result.Error = "a provider callback requires an authenticated staging claim"
		return result
	}
	if _, err := uuid.Parse(*input.CryptoProviderBindingID); err != nil {
		result.Error = "invalid provider binding"
		return result
	}
	tx, err := database.DB.Beginx()
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer tx.Rollback()
	created, addGraphEdge, err := createCryptoProviderCallbackTx(tx, input, authContext, &callback, payload)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if err := tx.Commit(); err != nil {
		result.Error = err.Error()
		return result
	}
	if created {
		if addGraphEdge {
			callbackGraph.Add(callback, callback, input.C2ProfileName, false)
		}
		notifyCryptoProviderCallbackCreated(callback, payload, authContext)
	}
	return callbackCreationResult(callback)
}

// Lock the binding before checking for an existing callback. This serializes two
// authenticated check-ins even after the first one consumes the staging row.
// No native operation or remote RPC runs while this transaction is held.
func createCryptoProviderCallbackTx(tx *sqlx.Tx, input MythicRPCCallbackCreateMessage, authContext RabbitMQAuthContext, callback *databaseStructs.Callback, payload databaseStructs.Payload) (bool, bool, error) {
	var scheme string
	if err := tx.Get(&scheme, `SELECT scheme FROM crypto_provider_binding
		WHERE id=$1 AND operation_id=$2 AND session_ref<>'' FOR UPDATE`,
		*input.CryptoProviderBindingID, authContext.OperationID); err != nil {
		return false, false, fmt.Errorf("provider session does not belong to this operation: %w", err)
	}
	var existing databaseStructs.Callback
	err := tx.Get(&existing, `SELECT * FROM callback WHERE crypto_provider_binding_id=$1 AND operation_id=$2`,
		*input.CryptoProviderBindingID, authContext.OperationID)
	if err == nil {
		if existing.RegisteredPayloadID != payload.ID {
			return false, false, errors.New("provider session is already bound to a different payload")
		}
		*callback = existing
		return false, false, saveCryptoProviderCallbackExchange(tx, input, existing)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, false, err
	}
	var stagingID int
	if err := tx.Get(&stagingID, `SELECT id FROM staginginfo
		WHERE staging_uuid=$1 AND payload_id=$2 AND crypto_provider_binding_id=$3 FOR UPDATE`,
		input.CryptoProviderStagingUUID, payload.ID, *input.CryptoProviderBindingID); err != nil {
		return false, false, fmt.Errorf("provider staging claim is unavailable: %w", err)
	}
	callback.CryptoProviderBindingID = sql.NullString{String: *input.CryptoProviderBindingID, Valid: true}
	callback.CryptoType = scheme
	callback.EncKey, callback.DecKey = nil, nil
	if authContext.EventStepInstanceID > 0 {
		callback.EventStepInstanceID.Valid = true
		callback.EventStepInstanceID.Int64 = int64(authContext.EventStepInstanceID)
	}
	statement, err := tx.PrepareNamed(`INSERT INTO callback
		(host,pid,ip,extra_info,sleep_info,external_ip,integrity_level,os,domain,architecture,process_name,registered_payload_id,
		operation_id,enc_key,dec_key,operator_id,active,crypto_type,description,agent_callback_id,"user",eventstepinstance_id,
		process_short_name,cwd,impersonation_context,crypto_provider_binding_id)
		VALUES (:host,:pid,:ip,:extra_info,:sleep_info,:external_ip,:integrity_level,:os,:domain,:architecture,:process_name,:registered_payload_id,
		:operation_id,:enc_key,:dec_key,:operator_id,:active,:crypto_type,:description,:agent_callback_id,:user,:eventstepinstance_id,
		:process_short_name,:cwd,:impersonation_context,:crypto_provider_binding_id) RETURNING *`)
	if err != nil {
		return false, false, err
	}
	defer statement.Close()
	if err := statement.Get(callback, callback); err != nil {
		return false, false, err
	}
	var apiTokenID sql.NullInt64
	if authContext.APITokensID > 0 {
		apiTokenID = sql.NullInt64{Int64: int64(authContext.APITokensID), Valid: true}
	}
	queries := []struct {
		query string
		args  []interface{}
	}{
		{`INSERT INTO loadedcommands (command_id,"version",callback_id,operator_id,apitokens_id)
			SELECT command_id,"version",$1,$2,$3 FROM payloadcommand WHERE payload_id=$4`,
			[]interface{}{callback.ID, callback.OperatorID, apiTokenID, payload.ID}},
		{`INSERT INTO callbackc2profiles (callback_id,c2_profile_id)
			SELECT $1,c2_profile_id FROM payloadc2profiles WHERE payload_id=$2`, []interface{}{callback.ID, payload.ID}},
		{`INSERT INTO c2profileparametersinstance
			(c2_profile_parameters_id,c2_profile_id,"value",enc_key,dec_key,callback_id,operation_id,crypto_provider_binding_id)
			SELECT c2_profile_parameters_id,c2_profile_id,"value",enc_key,dec_key,$1,$2,crypto_provider_binding_id
			FROM c2profileparametersinstance WHERE payload_id=$3`, []interface{}{callback.ID, callback.OperationID, payload.ID}},
		{`INSERT INTO payloadonhost (host,payload_id,operation_id) VALUES ($1,$2,$3)`,
			[]interface{}{callback.Host, payload.ID, callback.OperationID}},
	}
	for _, query := range queries {
		if _, err := tx.Exec(query.query, query.args...); err != nil {
			return false, false, err
		}
	}
	edges, err := tx.Exec(`INSERT INTO callbackgraphedge (source_id,destination_id,c2_profile_id,operation_id,metadata,apitokens_id)
		SELECT $1,$1,c2profile.id,$2,'',$3 FROM payloadc2profiles
		JOIN c2profile ON c2profile.id=payloadc2profiles.c2_profile_id
		WHERE payloadc2profiles.payload_id=$4 AND c2profile.name=$5 AND NOT c2profile.is_p2p`,
		callback.ID, callback.OperationID, apiTokenID, payload.ID, input.C2ProfileName)
	if err != nil {
		return false, false, err
	}
	if err := saveCryptoProviderCallbackExchange(tx, input, *callback); err != nil {
		return false, false, err
	}
	if _, err := tx.Exec(`DELETE FROM staginginfo WHERE id=$1`, stagingID); err != nil {
		return false, false, err
	}
	count, err := edges.RowsAffected()
	return true, count > 0, err
}

// Persist the authoritative callback route with the request that consumed the
// staged ciphertext, so recovery does not need the deleted staging row.
func saveCryptoProviderCallbackExchange(tx *sqlx.Tx, input MythicRPCCallbackCreateMessage, callback databaseStructs.Callback) error {
	result, err := tx.Exec(`UPDATE crypto_provider_exchange SET next_uuid=$1
		WHERE request_id=$2 AND binding_id=$3 AND route_uuid=$4`,
		callback.AgentCallbackID, input.CryptoProviderRequestID, *input.CryptoProviderBindingID, input.CryptoProviderStagingUUID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("provider check-in request does not match its authenticated staging claim")
	}
	return nil
}
