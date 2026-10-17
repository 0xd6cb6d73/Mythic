package provider

import "errors"

// ValidateSupportedSchemes checks an optional payload declaration. An empty
// declaration means the payload does not support any external crypto schemes.
func ValidateSupportedSchemes(schemes []string) error {
	if len(schemes) > 128 {
		return errors.New("supported_crypto_schemes must contain at most 128 schemes")
	}
	seen := make(map[string]bool, len(schemes))
	for _, scheme := range schemes {
		if !identifier.MatchString(scheme) || seen[scheme] {
			return errors.New("supported_crypto_schemes contains an invalid or duplicate scheme")
		}
		seen[scheme] = true
	}
	return nil
}
