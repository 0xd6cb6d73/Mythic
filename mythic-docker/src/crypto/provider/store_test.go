package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

func TestStoreRejectsInvalidRequestsBeforeDatabaseAccess(t *testing.T) {
	s := NewStore(nil)
	ctx := context.Background()
	key := StateKey{Namespace: "identity", StateID: "server-1"}
	if _, err := s.Load(ctx, 0, key); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("untrusted provider ID: %v", err)
	}
	for _, value := range []string{"", "space key", "new\nline", "null\x00byte", strings.Repeat("a", MaxStateIDBytes+1)} {
		if _, err := s.Load(ctx, 1, StateKey{Namespace: key.Namespace, StateID: value}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid state ID %q: %v", value, err)
		}
	}
	for _, value := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{`)} {
		if _, err := s.Create(ctx, 1, CreateStateRequest{StateKey: key, ProviderJSON: value}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid provider JSON: %v", err)
		}
	}
	if _, err := s.Acquire(ctx, 1, AcquireStateRequest{StateKey: key, ExpectedOwnerEpoch: -1}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("negative epoch: %v", err)
	}
	if _, err := s.LookupResult(ctx, 1, LookupResultRequest{StateKey: key, RequestID: "request", InputDigest: strings.Repeat("A", 64)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("noncanonical digest: %v", err)
	}
	if _, err := validateStateData(make([]byte, MaxStateBlobBytes+1), nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversize checkpoint: %v", err)
	}
	result := bytes.Repeat([]byte{'a'}, MaxResultBytes+1)
	result[0], result[len(result)-1] = '"', '"'
	if _, err := s.Commit(ctx, 1, CommitStateRequest{
		StateKey: key, OwnerEpoch: 1, RequestID: "oversize-result",
		InputDigest: strings.Repeat("a", 64), Result: result,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversize result: %v", err)
	}
}

// These tests exercise PostgreSQL row locking, JSONB behavior, and rollback of
// the real migration. Set CRYPTO_PROVIDER_TEST_DSN to an isolated test database.
func TestStorePostgres(t *testing.T) {
	db := newStoreTestDB(t)
	s := NewStore(db)
	ctx := context.Background()

	t.Run("opaque state and provider isolation", func(t *testing.T) {
		key := StateKey{Namespace: "opaque", StateID: "server"}
		blob := []byte{0, 255, 128, '\n', '{', '}', 0}
		created, err := s.Create(ctx, 1, CreateStateRequest{
			StateKey: key, StateBlob: blob, ProviderJSON: json.RawMessage(`{"future":{"flag":true},"unknown":[1,2]}`),
		})
		if err != nil || !bytes.Equal(created.StateBlob, blob) || created.Revision != 0 || created.OwnerEpoch != 0 {
			t.Fatalf("create opaque state: state=%+v err=%v", created, err)
		}
		if _, err := s.Create(ctx, 1, CreateStateRequest{StateKey: key, StateBlob: []byte("overwrite")}); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("duplicate create: %v", err)
		}
		if _, err := s.Load(ctx, 2, key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("provider isolation: %v", err)
		}
		if _, err := s.Create(ctx, 2, CreateStateRequest{StateKey: key}); err != nil {
			t.Fatalf("separate provider scope: %v", err)
		}
		loaded, err := s.Load(ctx, 1, key)
		if err != nil || !bytes.Equal(loaded.StateBlob, blob) || !bytes.Contains(loaded.ProviderJSON, []byte(`"future"`)) {
			t.Fatalf("load exact checkpoint: state=%+v err=%v", loaded, err)
		}
		missing := StateKey{Namespace: key.Namespace, StateID: "missing"}
		if _, err := s.Acquire(ctx, 1, AcquireStateRequest{StateKey: missing}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("acquire must not create: %v", err)
		}
	})

	t.Run("atomic results retries and fencing", func(t *testing.T) {
		key := StateKey{Namespace: "journal", StateID: "server"}
		owner := createStoreOwner(t, s, key)
		req := storeCommitRequest(key, "request-1", owner.OwnerEpoch, 0, "checkpoint-1")
		first, err := s.Commit(ctx, 1, req)
		if err != nil || first.Cached || first.Revision != 1 {
			t.Fatalf("initial commit: result=%+v err=%v", first, err)
		}
		if _, err := s.LookupResult(ctx, 2, LookupResultRequest{StateKey: key, RequestID: req.RequestID, InputDigest: req.InputDigest}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("result provider isolation: %v", err)
		}
		newOwner, err := s.Acquire(ctx, 1, AcquireStateRequest{StateKey: key, ExpectedOwnerEpoch: owner.OwnerEpoch})
		if err != nil || newOwner.OwnerEpoch != 2 || newOwner.Revision != 1 {
			t.Fatalf("fence first owner: state=%+v err=%v", newOwner, err)
		}
		if _, err := s.Acquire(ctx, 1, AcquireStateRequest{StateKey: key, ExpectedOwnerEpoch: owner.OwnerEpoch}); !errors.Is(err, ErrStaleWriter) {
			t.Fatalf("repeated acquire must not increment twice: %v", err)
		}
		replay, err := s.Commit(ctx, 1, req)
		if err != nil || !replay.Cached || replay.Revision != first.Revision || !bytes.Equal(replay.Result, first.Result) {
			t.Fatalf("replay before stale checks: result=%+v err=%v", replay, err)
		}
		conflict := req
		conflict.InputDigest = strings.Repeat("b", 64)
		if _, err := s.Commit(ctx, 1, conflict); !errors.Is(err, ErrRequestConflict) {
			t.Fatalf("request ID input conflict: %v", err)
		}
		stale := storeCommitRequest(key, "request-2", owner.OwnerEpoch, 1, "stale-checkpoint")
		if _, err := s.Commit(ctx, 1, stale); !errors.Is(err, ErrStaleWriter) {
			t.Fatalf("old epoch commit: %v", err)
		}
		stale.OwnerEpoch = newOwner.OwnerEpoch
		stale.ExpectedRevision = 0
		if _, err := s.Commit(ctx, 1, stale); !errors.Is(err, ErrStaleWriter) {
			t.Fatalf("old revision commit: %v", err)
		}
		current, err := s.Load(ctx, 1, key)
		if err != nil || string(current.StateBlob) != "checkpoint-1" || current.Revision != 1 || current.OwnerEpoch != 2 {
			t.Fatalf("stale writes changed state: state=%+v err=%v", current, err)
		}
	})

	t.Run("large binary result survives commit and replay", func(t *testing.T) {
		key := StateKey{Namespace: "large-result", StateID: "server"}
		owner := createStoreOwner(t, s, key)
		// Exercise a full-sized binary message inside its base64 JSON envelope.
		message := bytes.Repeat([]byte{0, 255, 128, '\n'}, (32<<20)/4)
		encoded, err := json.Marshal(struct {
			Message []byte `json:"message"`
		}{Message: message})
		if err != nil {
			t.Fatal(err)
		}
		req := storeCommitRequest(key, "large-message", owner.OwnerEpoch, 0, "checkpoint")
		req.Result = encoded
		first, err := s.Commit(ctx, 1, req)
		if err != nil || first.Cached {
			t.Fatalf("commit large result: %v", err)
		}
		lookup, err := s.LookupResult(ctx, 1, LookupResultRequest{
			StateKey: key, RequestID: req.RequestID, InputDigest: req.InputDigest,
		})
		if err != nil {
			t.Fatalf("lookup large result: %v", err)
		}
		replay, err := s.Commit(ctx, 1, req)
		if err != nil || !replay.Cached || replay.Revision != first.Revision ||
			!bytes.Equal(first.Result, lookup.Result) || !bytes.Equal(first.Result, replay.Result) {
			t.Fatalf("replay large result: %v", err)
		}
		var decoded struct {
			Message []byte `json:"message"`
		}
		if err := json.Unmarshal(replay.Result, &decoded); err != nil || !bytes.Equal(decoded.Message, message) {
			t.Fatalf("large binary result changed: %v", err)
		}
	})

	t.Run("failed result insert rolls back checkpoint", func(t *testing.T) {
		key := StateKey{Namespace: "rollback", StateID: "server"}
		owner := createStoreOwner(t, s, key)
		req := storeCommitRequest(key, "failed-result", owner.OwnerEpoch, 0, "must-rollback")
		// Valid JSON that PostgreSQL JSONB cannot represent. This fails the
		// result insertion after the checkpoint UPDATE has already executed.
		req.Result = json.RawMessage(`{"unsupported":"\u0000"}`)
		if _, err := s.Commit(ctx, 1, req); err == nil {
			t.Fatal("expected JSONB insertion failure")
		}
		state, err := s.Load(ctx, 1, key)
		if err != nil || state.Revision != 0 || string(state.StateBlob) != "initial" {
			t.Fatalf("checkpoint escaped rolled back transaction: state=%+v err=%v", state, err)
		}
		if _, err := s.LookupResult(ctx, 1, LookupResultRequest{StateKey: key, RequestID: req.RequestID, InputDigest: req.InputDigest}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("failed transaction retained result: %v", err)
		}
	})

	t.Run("concurrent retries commit once", func(t *testing.T) {
		key := StateKey{Namespace: "concurrent", StateID: "same-request"}
		owner := createStoreOwner(t, s, key)
		req := storeCommitRequest(key, "same-request", owner.OwnerEpoch, 0, "once")
		results := make(chan *CommitResult, 2)
		errorsCh := make(chan error, 2)
		start := make(chan struct{})
		for range 2 {
			go func() {
				<-start
				result, err := s.Commit(ctx, 1, req)
				results <- result
				errorsCh <- err
			}()
		}
		close(start)
		cached := 0
		for range 2 {
			if err := <-errorsCh; err != nil {
				t.Fatalf("concurrent retry: %v", err)
			}
			result := <-results
			if result.Cached {
				cached++
			}
			if result.Revision != 1 {
				t.Fatalf("retry advanced revision: %+v", result)
			}
		}
		if cached != 1 {
			t.Fatalf("cached replies = %d, want 1", cached)
		}
	})

	t.Run("concurrent writers cannot overwrite", func(t *testing.T) {
		key := StateKey{Namespace: "concurrent", StateID: "different-requests"}
		owner := createStoreOwner(t, s, key)
		var wg sync.WaitGroup
		errorsCh := make(chan error, 2)
		start := make(chan struct{})
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.Commit(ctx, 1, storeCommitRequest(key, fmt.Sprintf("writer-%d", i), owner.OwnerEpoch, 0, fmt.Sprintf("writer-%d", i)))
				errorsCh <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errorsCh)
		successes, stale := 0, 0
		for err := range errorsCh {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrStaleWriter):
				stale++
			default:
				t.Fatalf("concurrent writer: %v", err)
			}
		}
		if successes != 1 || stale != 1 {
			t.Fatalf("successes=%d stale=%d, want one each", successes, stale)
		}
		state, err := s.Load(ctx, 1, key)
		if err != nil || state.Revision != 1 {
			t.Fatalf("state after concurrent writes: state=%+v err=%v", state, err)
		}
	})

	t.Run("cancelled mutation leaves state unchanged", func(t *testing.T) {
		key := StateKey{Namespace: "cancel", StateID: "server"}
		owner := createStoreOwner(t, s, key)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.Commit(cancelled, 1, storeCommitRequest(key, "cancelled", owner.OwnerEpoch, 0, "never")); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled commit: %v", err)
		}
		state, err := s.Load(ctx, 1, key)
		if err != nil || state.Revision != 0 || string(state.StateBlob) != "initial" {
			t.Fatalf("cancelled commit changed state: state=%+v err=%v", state, err)
		}
	})
}

func createStoreOwner(t *testing.T, s *Store, key StateKey) *StoredState {
	t.Helper()
	if _, err := s.Create(context.Background(), 1, CreateStateRequest{StateKey: key, StateBlob: []byte("initial")}); err != nil {
		t.Fatalf("create owner state: %v", err)
	}
	owner, err := s.Acquire(context.Background(), 1, AcquireStateRequest{StateKey: key, ExpectedOwnerEpoch: 0})
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	return owner
}

func storeCommitRequest(key StateKey, requestID string, epoch, revision int64, state string) CommitStateRequest {
	return CommitStateRequest{
		StateKey: key, OwnerEpoch: epoch, ExpectedRevision: revision,
		RequestID: requestID, InputDigest: strings.Repeat("a", 64), StateBlob: []byte(state),
		ProviderJSON: json.RawMessage(`{"extension":{"version":2}}`),
		Result:       json.RawMessage(`{ "data": "AP+A", "receipt": "stable" }`),
	}
}

func newStoreTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	dsn := os.Getenv("CRYPTO_PROVIDER_TEST_DSN")
	if dsn == "" {
		t.Skip("set CRYPTO_PROVIDER_TEST_DSN to run PostgreSQL transaction tests")
	}
	admin, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	schema := "crypto_store_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA ` + pq.QuoteIdentifier(schema)); err != nil {
		admin.Close()
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	})
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		dsn += " search_path=" + schema
	} else {
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
	}
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect to isolated schema: %v", err)
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxLifetime(time.Minute)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE consuming_container(id integer PRIMARY KEY);
		CREATE TABLE payloadtype(id integer PRIMARY KEY);
		CREATE TABLE operation(id integer PRIMARY KEY);
		CREATE TABLE buildparameterinstance(id integer PRIMARY KEY);
		CREATE TABLE c2profileparametersinstance(id integer PRIMARY KEY);
		CREATE TABLE staginginfo(id integer PRIMARY KEY);
		CREATE TABLE callback(id integer PRIMARY KEY);
		INSERT INTO consuming_container(id) VALUES (1),(2);`)
	if err != nil {
		t.Fatalf("create migration prerequisites: %v", err)
	}
	migration, err := os.ReadFile("../../database/migrations/003003027_3.3.27.sql")
	if err != nil {
		t.Fatalf("read crypto provider migration: %v", err)
	}
	up := strings.SplitN(string(migration), "-- +migrate Down", 2)[0]
	up = strings.ReplaceAll(up, "public.", pq.QuoteIdentifier(schema)+".")
	if _, err := db.Exec(up); err != nil {
		t.Fatalf("apply crypto provider migration: %v", err)
	}
	return db
}
