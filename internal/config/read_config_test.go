// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"strings"
	"testing"
)

func TestConfigurationLimitDoesNotHideTrailingData(t *testing.T) {
	tests := []struct {
		name, input string
		valid       bool
	}{
		{"single object", "{}\n", true},
		{"object at limit", "{}" + strings.Repeat(" ", maxConfigurationBytes-2), true},
		{"trailing beyond limit", "{}" + strings.Repeat(" ", maxConfigurationBytes-2) + "{\"extra\":true}", false},
		{"oversized whitespace", "{}" + strings.Repeat(" ", maxConfigurationBytes), false},
		{"two objects", "{} {}", false},
		{"unknown setting", "{\"UnexpectedSetting\":true}", false},
		{"null", "null", false},
		{"array", "[]", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeConfiguration(strings.NewReader(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
