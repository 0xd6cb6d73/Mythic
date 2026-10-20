package provider

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateSupportedSchemes(t *testing.T) {
	maximum := make([]string, 128)
	for i := range maximum {
		maximum[i] = fmt.Sprintf("scheme-%d", i)
	}
	for _, test := range []struct {
		name    string
		schemes []string
		invalid bool
	}{
		{"omitted", nil, false},
		{"empty", []string{}, false},
		{"valid identifiers", []string{"example", "Other_1.2-test", "0"}, false},
		{"case sensitive", []string{"example", "Example"}, false},
		{"maximum count", maximum, false},
		{"maximum length", []string{strings.Repeat("a", 128)}, false},
		{"too many", append(append([]string{}, maximum...), "extra"), true},
		{"duplicate", []string{"example", "example"}, true},
		{"empty identifier", []string{""}, true},
		{"qualified selection", []string{"provider:worker:example"}, true},
		{"leading punctuation", []string{"-example"}, true},
		{"space", []string{"example "}, true},
		{"unicode", []string{"éxample"}, true},
		{"too long", []string{strings.Repeat("a", 129)}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateSupportedSchemes(test.schemes); (err != nil) != test.invalid {
				t.Fatalf("ValidateSupportedSchemes() = %v; invalid=%v", err, test.invalid)
			}
		})
	}
}
