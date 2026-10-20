package rabbitmq

import (
	"errors"

	"github.com/its-a-feature/Mythic/database"
)

// Provider-enabled payloads must not reach legacy fallback through a transport
// that was never configured on the payload. Configured legacy routes remain
// valid alongside configured provider routes; legacy-only payloads keep their
// existing route handling.
func validatePayloadCryptoProviderRoute(payloadID int, c2 string) error {
	if c2 == "" {
		return nil
	}
	var invalid bool
	err := database.DB.Get(&invalid, `SELECT EXISTS (
		SELECT 1 FROM buildparameterinstance WHERE payload_id=$1 AND crypto_provider_binding_id IS NOT NULL
		UNION ALL
		SELECT 1 FROM c2profileparametersinstance WHERE payload_id=$1 AND crypto_provider_binding_id IS NOT NULL
	) AND NOT EXISTS (
		SELECT 1 FROM payloadc2profiles p JOIN c2profile c ON c.id=p.c2_profile_id
		WHERE p.payload_id=$1 AND c.name=$2
	)`, payloadID, c2)
	if err != nil {
		return err
	}
	if invalid {
		return errors.New("payload C2 route is not configured")
	}
	return nil
}
