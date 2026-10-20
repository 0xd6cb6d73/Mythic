package rabbitmq

import (
	"encoding/json"
	"fmt"
	"slices"

	mythicCrypto "github.com/its-a-feature/Mythic/crypto"
	"github.com/its-a-feature/Mythic/crypto/provider"
	databaseStructs "github.com/its-a-feature/Mythic/database/structs"
)

func supportedCryptoSchemesForSync(payloadType PayloadType) (databaseStructs.MythicJSONArray, error) {
	if err := provider.ValidateSupportedSchemes(payloadType.SupportedCryptoSchemes); err != nil {
		return nil, err
	}
	schemes := payloadType.SupportedCryptoSchemes
	if schemes == nil {
		schemes = []string{}
	}
	encoded, err := json.Marshal(schemes)
	return databaseStructs.MythicJSONArray(encoded), err
}

func validatePayloadCryptoScheme(payloadType databaseStructs.Payloadtype, value string) error {
	_, scheme, external, err := provider.ParseSelection(value)
	if err != nil || !external {
		return err
	}
	var supported []string
	if len(payloadType.SupportedCryptoSchemes) > 0 {
		if err := json.Unmarshal(payloadType.SupportedCryptoSchemes, &supported); err != nil {
			return fmt.Errorf("invalid supported_crypto_schemes for payload type %q", payloadType.Name)
		}
	}
	if err := provider.ValidateSupportedSchemes(supported); err != nil {
		return fmt.Errorf("invalid supported_crypto_schemes for payload type %q: %w", payloadType.Name, err)
	}
	if !slices.Contains(supported, scheme) {
		return fmt.Errorf("crypto scheme %q is not supported by payload type %q", scheme, payloadType.Name)
	}
	return nil
}

// Payload compatibility is checked before provider discovery or prepare_profile,
// so API clients, imports and rebuilds cannot create unsupported provider state.
func prepareCryptoProviderKeysForPayload(payloadType databaseStructs.Payloadtype, value string, operationID int, authContext RabbitMQAuthContext) (mythicCrypto.CryptoKeys, error) {
	if err := validatePayloadCryptoScheme(payloadType, value); err != nil {
		return mythicCrypto.CryptoKeys{}, err
	}
	return PrepareCryptoProviderKeys(value, operationID, authContext)
}
