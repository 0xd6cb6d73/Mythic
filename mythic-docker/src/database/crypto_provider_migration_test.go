package database

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	migrate "github.com/rubenv/sql-migrate"
)

const cryptoProviderMigrationVersion int64 = 3003027

// Each case creates its own database because the initial schema and historical
// migrations explicitly address public. The opt-in DSN must permit CREATE DB.
func TestCryptoProviderMigration(t *testing.T) {
	dsn := os.Getenv("CRYPTO_PROVIDER_TEST_DSN")
	if dsn == "" {
		t.Skip("set CRYPTO_PROVIDER_TEST_DSN to a disposable PostgreSQL server")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	for _, upgraded := range []bool{false, true} {
		name := "fresh"
		if upgraded {
			name = "upgrade"
		}
		t.Run(name, func(t *testing.T) {
			databaseName := "crypto_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(databaseName)); err != nil {
				t.Fatal(err)
			}
			parsed, err := url.Parse(dsn)
			if err != nil {
				t.Fatal(err)
			}
			parsed.Path = "/" + databaseName
			db, err := sql.Open("postgres", parsed.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				db.Close()
				if _, err := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(databaseName) + " WITH (FORCE)"); err != nil {
					t.Error(err)
				}
			})
			if _, err := db.Exec(Schema); err != nil {
				t.Fatalf("initial schema: %v", err)
			}
			// Initialize reconnects after loading Schema, which resets search_path.
			if _, err := db.Exec("SET search_path TO public"); err != nil {
				t.Fatal(err)
			}
			migrations := &migrate.FileMigrationSource{Dir: "migrations"}
			migrate.SetSchema("public")
			migrate.SetTable("mythic_server_migration_tracking")
			if upgraded {
				if _, err := migrate.ExecVersion(db, "postgres", migrations, migrate.Up, 3003026); err != nil {
					t.Fatalf("baseline migrations: %v", err)
				}
				if _, err := db.Exec(`INSERT INTO consuming_container(name,type) VALUES ('legacy-webhook','webhook')`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO payloadtype(name,mythic_encrypts) VALUES ('legacy-agent',true)`); err != nil {
					t.Fatal(err)
				}
			}
			applied, err := migrate.ExecVersion(db, "postgres", migrations, migrate.Up, cryptoProviderMigrationVersion)
			if err != nil {
				t.Fatalf("crypto migration: %v", err)
			}
			if upgraded {
				if applied != 1 {
					t.Fatalf("expected one migration from the PR baseline, applied %d", applied)
				}
				var capabilities string
				if err := db.QueryRow(`SELECT crypto_capabilities::text FROM consuming_container WHERE name='legacy-webhook'`).Scan(&capabilities); err != nil || capabilities != "{}" {
					t.Fatalf("legacy capabilities: %q, %v", capabilities, err)
				}
				var schemes string
				if err := db.QueryRow(`SELECT supported_crypto_schemes::text FROM payloadtype WHERE name='legacy-agent'`).Scan(&schemes); err != nil || schemes != "[]" {
					t.Fatalf("legacy supported schemes: %q, %v", schemes, err)
				}
			}
			for _, table := range []string{"buildparameterinstance", "c2profileparametersinstance", "staginginfo", "callback"} {
				var count int
				if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name='crypto_provider_binding_id' AND data_type='uuid' AND is_nullable='YES'`, table).Scan(&count); err != nil || count != 1 {
					t.Fatalf("nullable binding column on %s: %d, %v", table, count, err)
				}
			}
			for _, table := range []string{"crypto_provider_binding", "crypto_provider_state", "crypto_provider_result", "crypto_provider_exchange"} {
				var present bool
				if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&present); err != nil || !present {
					t.Fatalf("missing %s: %v", table, err)
				}
			}
			var pendingIndex string
			if err := db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname='public'
				AND indexname='crypto_provider_exchange_pending'`).Scan(&pendingIndex); err != nil ||
				!strings.Contains(pendingIndex, "(binding_id, route_uuid)") || !strings.Contains(pendingIndex, "WHERE (response IS NULL)") {
				t.Fatalf("missing pending-exchange partial index: %q, %v", pendingIndex, err)
			}
			var dispatchType string
			if err := db.QueryRow(`SELECT data_type FROM information_schema.columns WHERE table_schema='public'
				AND table_name='crypto_provider_exchange' AND column_name='dispatch_response'`).Scan(&dispatchType); err != nil || dispatchType != "bytea" {
				t.Fatalf("missing durable application response: %q, %v", dispatchType, err)
			}
			// Down includes its target migration, so stop at the feature itself.
			rolledBack, err := migrate.ExecVersion(db, "postgres", migrations, migrate.Down, cryptoProviderMigrationVersion)
			if err != nil {
				t.Fatalf("crypto migration rollback: %v", err)
			}
			if rolledBack != 1 {
				t.Fatalf("expected one migration rollback, rolled back %d", rolledBack)
			}
			var baselineApplied int
			if err := db.QueryRow(`SELECT count(*) FROM mythic_server_migration_tracking WHERE id='003003026_3.3.26.sql'`).Scan(&baselineApplied); err != nil || baselineApplied != 1 {
				t.Fatalf("rollback removed baseline migration: %d, %v", baselineApplied, err)
			}
			for _, table := range []string{"crypto_provider_binding", "crypto_provider_state", "crypto_provider_result", "crypto_provider_exchange"} {
				var present bool
				if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&present); err != nil || present {
					t.Fatalf("%s remains after rollback: %v, %v", table, present, err)
				}
			}
			for table, column := range map[string]string{
				"consuming_container":         "crypto_capabilities",
				"payloadtype":                 "supported_crypto_schemes",
				"buildparameterinstance":      "crypto_provider_binding_id",
				"c2profileparametersinstance": "crypto_provider_binding_id",
				"staginginfo":                 "crypto_provider_binding_id",
				"callback":                    "crypto_provider_binding_id",
			} {
				var count int
				if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=$2`, table, column).Scan(&count); err != nil || count != 0 {
					t.Fatalf("%s.%s remains after rollback: %d, %v", table, column, count, err)
				}
			}
			if upgraded {
				for table, name := range map[string]string{"consuming_container": "legacy-webhook", "payloadtype": "legacy-agent"} {
					var count int
					if err := db.QueryRow("SELECT count(*) FROM "+pq.QuoteIdentifier(table)+" WHERE name=$1", name).Scan(&count); err != nil || count != 1 {
						t.Fatalf("rollback lost legacy %s: %d, %v", table, count, err)
					}
				}
			}
		})
	}
}
