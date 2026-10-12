// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package ttlstore

import (
	"fmt"
	"math"
	"time"
)

type limits struct {
	MaxSize         int
	MaxBytes        int
	MaxValuesPerKey int
	MaxValueBytes   int
}

func normalizedLimits(size, bytes, values, valueBytes int) limits {
	if size <= 0 {
		size = DefaultMaxSize
	}
	if bytes <= 0 {
		bytes = DefaultMaxBytes
	}
	if values <= 0 {
		values = DefaultMaxValuesPerKey
	}
	if valueBytes <= 0 {
		valueBytes = DefaultMaxValueBytes
	}
	return limits{size, bytes, values, valueBytes}
}

func validateBatch(checks []Condition, ops []Mutation, lim limits) error {
	if len(checks) > MaxBatchSize || len(ops) > MaxBatchSize {
		return fmt.Errorf("%w: too many operations", ErrInvalidOperation)
	}
	validKey := func(key string) bool { return len(key) > 0 && len(key) <= MaxKeyBytes }
	for _, c := range checks {
		if !validKey(c.Key) || len(c.Value) > lim.MaxValueBytes {
			return fmt.Errorf("%w: invalid condition", ErrInvalidOperation)
		}
	}
	for _, op := range ops {
		if !validKey(op.Key) || len(op.Value) > lim.MaxValueBytes || op.MaxValues < 0 {
			return fmt.Errorf("%w: invalid key, value, or limit", ErrInvalidOperation)
		}
		switch op.Kind {
		case SetValue, AddValue:
			if op.TTL == 0 || op.Value == nil {
				return fmt.Errorf("%w: value and positive TTL required", ErrInvalidOperation)
			}
			if uint64(op.TTL)+uint64(time.Now().Unix()) > math.MaxUint32 {
				return fmt.Errorf("%w: expiration would overflow storage timestamp", ErrInvalidOperation)
			}
		case RemoveValue:
			if op.Value == nil {
				return fmt.Errorf("%w: value required", ErrInvalidOperation)
			}
		case DeleteKey:
		default:
			return fmt.Errorf("%w: unknown mutation", ErrInvalidOperation)
		}
	}
	return nil
}
