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

func TestPayloadCryptoSchemesMigration(t *testing.T) {
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
			databaseName := "crypto_schemes_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
				if _, err := db.Exec(`INSERT INTO payloadtype(name,mythic_encrypts) VALUES ('legacy-agent',true)`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := migrate.ExecVersion(db, "postgres", migrations, migrate.Up, cryptoProviderMigrationVersion); err != nil {
				t.Fatalf("schemes migration: %v", err)
			}
			if !upgraded {
				if _, err := db.Exec(`INSERT INTO payloadtype(name,mythic_encrypts) VALUES ('legacy-agent',true)`); err != nil {
					t.Fatal(err)
				}
			}
			var schemes string
			if err := db.QueryRow(`SELECT supported_crypto_schemes::text FROM payloadtype WHERE name='legacy-agent'`).Scan(&schemes); err != nil || schemes != "[]" {
				t.Fatalf("legacy default=%q err=%v", schemes, err)
			}
			if _, err := db.Exec(`UPDATE payloadtype SET supported_crypto_schemes='["example"]' WHERE name='legacy-agent'`); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []string{`{}`, `null`, `"example"`, "[" + strings.Repeat(`"example",`, 128) + `"extra"]`} {
				if _, err := db.Exec(`UPDATE payloadtype SET supported_crypto_schemes=$1 WHERE name='legacy-agent'`, invalid); err == nil {
					t.Fatalf("invalid declaration accepted by schema: %s", invalid)
				}
			}
			if _, err := migrate.ExecVersion(db, "postgres", migrations, migrate.Down, cryptoProviderMigrationVersion); err != nil {
				t.Fatalf("schemes rollback: %v", err)
			}
			var count int
			if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='payloadtype' AND column_name='supported_crypto_schemes'`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("column remains after rollback: count=%d err=%v", count, err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM payloadtype WHERE name='legacy-agent'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("rollback lost legacy payload type: count=%d err=%v", count, err)
			}
		})
	}
}
