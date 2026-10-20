package databaseStructs

import "database/sql"

type Staginginfo struct {
	ID                      int            `db:"id"`
	SessionID               string         `db:"session_id"`
	EncKey                  *[]byte        `db:"enc_key"`
	DecKey                  *[]byte        `db:"dec_key"`
	CryptoType              string         `db:"crypto_type"`
	CryptoProviderBindingID sql.NullString `db:"crypto_provider_binding_id"`
	StagingUuID             string         `db:"staging_uuid"`
	PayloadID               int            `db:"payload_id"`
	Payload                 Payload        `db:"payload"`
}
