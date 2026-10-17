package provider

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/jmoiron/sqlx"
)

// Store persists opaque state and immutable operation results. Its callers must
// resolve providerID from authenticated container identity before calling it.
// It never interprets native checkpoints or writes their contents to logs.
type Store struct {
	db *sqlx.DB
}

func NewStore(db *sqlx.DB) *Store { return &Store{db: db} }

const stateColumns = `namespace, state_id, state_blob, provider_json, revision, owner_epoch, updated_at`

func (s *Store) Load(ctx context.Context, providerID int, key StateKey) (*StoredState, error) {
	if err := validateStateKey(providerID, key); err != nil {
		return nil, err
	}
	var state StoredState
	err := s.db.GetContext(ctx, &state, `SELECT `+stateColumns+` FROM crypto_provider_state
		WHERE provider_id=$1 AND namespace=$2 AND state_id=$3`, providerID, key.Namespace, key.StateID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load crypto provider state: %w", err)
	}
	return &state, nil
}

// Create never loads or overwrites an existing state. New objects start at
// revision and epoch zero; acquire ownership before committing a mutation.
func (s *Store) Create(ctx context.Context, providerID int, req CreateStateRequest) (*StoredState, error) {
	if err := validateStateKey(providerID, req.StateKey); err != nil {
		return nil, err
	}
	providerJSON, err := validateStateData(req.StateBlob, req.ProviderJSON)
	if err != nil {
		return nil, err
	}
	var state StoredState
	err = s.db.GetContext(ctx, &state, `INSERT INTO crypto_provider_state
		(provider_id, namespace, state_id, state_blob, provider_json, revision, owner_epoch)
		VALUES ($1,$2,$3,$4,$5::jsonb,0,0)
		ON CONFLICT (provider_id, namespace, state_id) DO NOTHING RETURNING `+stateColumns,
		providerID, req.Namespace, req.StateID, nonNilBytes(req.StateBlob), string(providerJSON))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		return nil, fmt.Errorf("create crypto provider state: %w", err)
	}
	return &state, nil
}

// Acquire fences earlier writers without changing the state revision. A caller
// restoring a native handle must commit its activated checkpoint before use.
func (s *Store) Acquire(ctx context.Context, providerID int, req AcquireStateRequest) (*StoredState, error) {
	if err := validateStateKey(providerID, req.StateKey); err != nil {
		return nil, err
	}
	if req.ExpectedOwnerEpoch < 0 || req.ExpectedOwnerEpoch == math.MaxInt64 {
		return nil, ErrInvalidInput
	}
	var state StoredState
	err := s.db.GetContext(ctx, &state, `UPDATE crypto_provider_state
		SET owner_epoch=owner_epoch+1, updated_at=clock_timestamp()
		WHERE provider_id=$1 AND namespace=$2 AND state_id=$3 AND owner_epoch=$4
		RETURNING `+stateColumns, providerID, req.Namespace, req.StateID, req.ExpectedOwnerEpoch)
	if errors.Is(err, sql.ErrNoRows) {
		if _, loadErr := s.Load(ctx, providerID, req.StateKey); loadErr != nil {
			return nil, loadErr
		}
		return nil, ErrStaleWriter
	}
	if err != nil {
		return nil, fmt.Errorf("acquire crypto provider state: %w", err)
	}
	return &state, nil
}

// Commit atomically replaces one state and records its exact operation outcome.
// A matching immutable result wins over stale revision/epoch checks on retries.
// JSONB may normalize JSON formatting; opaque bytes inside state_blob and JSON
// string values are preserved. The first reply uses the stored JSON too.
func (s *Store) Commit(ctx context.Context, providerID int, req CommitStateRequest) (*CommitResult, error) {
	lookup := LookupResultRequest{StateKey: req.StateKey, RequestID: req.RequestID, InputDigest: req.InputDigest}
	if err := validateLookup(providerID, lookup); err != nil {
		return nil, err
	}
	if req.ExpectedRevision < 0 || req.ExpectedRevision == math.MaxInt64 || req.OwnerEpoch <= 0 {
		return nil, ErrInvalidInput
	}
	providerJSON, err := validateStateData(req.StateBlob, req.ProviderJSON)
	if err != nil {
		return nil, err
	}
	if len(req.Result) == 0 || len(req.Result) > MaxResultBytes || !json.Valid(req.Result) {
		return nil, ErrInvalidInput
	}
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin crypto provider commit: %w", err)
	}
	defer tx.Rollback()
	var head struct {
		Revision   int64 `db:"revision"`
		OwnerEpoch int64 `db:"owner_epoch"`
	}
	err = tx.GetContext(ctx, &head, `SELECT revision, owner_epoch FROM crypto_provider_state
		WHERE provider_id=$1 AND namespace=$2 AND state_id=$3 FOR UPDATE`,
		providerID, req.Namespace, req.StateID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock crypto provider state: %w", err)
	}
	// Look up after taking the state lock, so concurrent retries observe the
	// preceding transaction's result instead of trying the mutation again.
	prior, err := lookupResult(ctx, tx, providerID, lookup)
	if err == nil {
		return &CommitResult{Revision: prior.Revision, Result: prior.Result, Cached: true}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if head.Revision != req.ExpectedRevision || head.OwnerEpoch != req.OwnerEpoch {
		return nil, ErrStaleWriter
	}
	revision := head.Revision + 1
	_, err = tx.ExecContext(ctx, `UPDATE crypto_provider_state
		SET state_blob=$4, provider_json=$5::jsonb, revision=$6, updated_at=clock_timestamp()
		WHERE provider_id=$1 AND namespace=$2 AND state_id=$3`,
		providerID, req.Namespace, req.StateID, nonNilBytes(req.StateBlob), string(providerJSON), revision)
	if err != nil {
		return nil, fmt.Errorf("update crypto provider state: %w", err)
	}
	var result json.RawMessage
	err = tx.GetContext(ctx, &result, `INSERT INTO crypto_provider_result
		(provider_id, namespace, state_id, request_id, input_digest, result, revision)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7) RETURNING result`,
		providerID, req.Namespace, req.StateID, req.RequestID, req.InputDigest, string(req.Result), revision)
	if err != nil {
		return nil, fmt.Errorf("record crypto provider result: %w", err)
	}
	if err = tx.Commit(); err != nil {
		// The caller must resolve an ambiguous acknowledgement by LookupResult,
		// never by publishing a locally retained result or blindly repeating work.
		return nil, fmt.Errorf("commit crypto provider state: %w", err)
	}
	return &CommitResult{Revision: revision, Result: result}, nil
}

func (s *Store) LookupResult(ctx context.Context, providerID int, req LookupResultRequest) (*OperationResult, error) {
	if err := validateLookup(providerID, req); err != nil {
		return nil, err
	}
	return lookupResult(ctx, s.db, providerID, req)
}

func lookupResult(ctx context.Context, db sqlx.QueryerContext, providerID int, req LookupResultRequest) (*OperationResult, error) {
	var result OperationResult
	err := sqlx.GetContext(ctx, db, &result, `SELECT namespace, state_id, request_id, input_digest, result, revision, created_at
		FROM crypto_provider_result WHERE provider_id=$1 AND namespace=$2 AND state_id=$3 AND request_id=$4`,
		providerID, req.Namespace, req.StateID, req.RequestID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load crypto provider result: %w", err)
	}
	if result.InputDigest != req.InputDigest {
		return nil, ErrRequestConflict
	}
	return &result, nil
}

func validateStateKey(providerID int, key StateKey) error {
	if providerID <= 0 || !validIdentifier(key.Namespace, MaxNamespaceBytes) || !validIdentifier(key.StateID, MaxStateIDBytes) {
		return ErrInvalidInput
	}
	return nil
}

func validateLookup(providerID int, req LookupResultRequest) error {
	if err := validateStateKey(providerID, req.StateKey); err != nil {
		return err
	}
	if !validIdentifier(req.RequestID, MaxRequestIDBytes) || len(req.InputDigest) != 64 || req.InputDigest != strings.ToLower(req.InputDigest) {
		return ErrInvalidInput
	}
	if _, err := hex.DecodeString(req.InputDigest); err != nil {
		return ErrInvalidInput
	}
	return nil
}

func validIdentifier(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:/-", c)) {
			return false
		}
	}
	return true
}

func validateStateData(blob []byte, providerJSON json.RawMessage) (json.RawMessage, error) {
	if len(blob) > MaxStateBlobBytes || len(providerJSON) > MaxProviderJSONBytes {
		return nil, ErrInvalidInput
	}
	if len(providerJSON) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid(providerJSON) || strings.TrimSpace(string(providerJSON))[0] != '{' {
		return nil, ErrInvalidInput
	}
	return providerJSON, nil
}

func nonNilBytes(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}
