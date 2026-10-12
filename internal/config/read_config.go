// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const maxConfigurationBytes = 1 << 20

// Read one complete configuration before decoding. The extra byte distinguishes
// actual EOF from an oversized file whose trailing content is beyond a limit.
func decodeConfiguration(source io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(source, maxConfigurationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigurationBytes {
		return nil, errors.New("configuration exceeds the 1 MiB limit")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, errors.New("configuration must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("configuration must contain exactly one JSON object")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}
