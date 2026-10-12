// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package ttlstore

import "errors"

var (
	ErrCapacity         = errors.New("TTL store capacity exceeded")
	ErrInvalidOperation = errors.New("invalid TTL store operation")
	ErrLegacyFormat     = errors.New("unsupported TTL store format; explicitly migrate legacy data before starting")
)

const (
	DefaultMaxSize         = 100000
	DefaultMaxBytes        = 32 << 20
	DefaultMaxValuesPerKey = 16
	DefaultMaxValueBytes   = 4096
	MaxKeyBytes            = 256
	MaxBatchSize           = 32
)

// Condition requires a key to contain exactly Value, or no live values when
// Value is nil. Conditions and mutations are evaluated in one atomic operation.
type Condition struct {
	Key   string
	Value []byte
}

type MutationKind string

const (
	SetValue    MutationKind = "set"
	AddValue    MutationKind = "add"
	RemoveValue MutationKind = "remove"
	DeleteKey   MutationKind = "delete"
)

type Mutation struct {
	Kind  MutationKind
	Key   string
	Value []byte
	TTL   uint32
	// MaxValues optionally tightens the store's per-key limit for an Add.
	MaxValues int
}

type TtlStore interface {
	// adds val to a set of values; adding an existing value refreshes its TTL
	Add(key string, val []byte, ttl uint32) error

	// associates val with key, replacing any other values
	Set(key string, val []byte, ttl uint32) error

	// gets all keys starting with prefix
	List(prefix string) (keys []string, err error)

	// checks if key has any non-expired values
	Exists(key string) (exists bool, err error)

	// gets all non-expired values associated with key
	Values(key string) (vals [][]byte, err error)

	// gets the first non-expired value associated with key
	Get(key string) (val []byte, err error)

	// unassociates val with key, leaving any other values
	Remove(key string, val []byte) error

	// deletes all values associated with key
	Delete(key string) error

	// Apply atomically checks all conditions and performs all mutations. A false
	// result means a condition changed; no mutations were made. Capacity and
	// validation errors also leave the requested data unchanged.
	Apply(conditions []Condition, mutations []Mutation) (bool, error)
}

type Prefixed struct {
	Store  TtlStore
	Prefix string
}

func (p *Prefixed) WithPrefix(key string) string {
	return p.Prefix + key
}

func (p *Prefixed) Add(key string, val []byte, ttl uint32) error {
	return p.Store.Add(p.WithPrefix(key), val, ttl)
}

func (p *Prefixed) Set(key string, val []byte, ttl uint32) error {
	return p.Store.Set(p.WithPrefix(key), val, ttl)
}

func (p *Prefixed) List(prefix string) (keys []string, err error) {
	keys, err = p.Store.List(p.WithPrefix(prefix))
	for i, v := range keys {
		keys[i] = v[len(p.Prefix):]
	}
	return
}

func (p *Prefixed) Exists(key string) (exists bool, err error) {
	return p.Store.Exists(p.WithPrefix(key))
}

func (p *Prefixed) Values(key string) (vals [][]byte, err error) {
	return p.Store.Values(p.WithPrefix(key))
}

func (p *Prefixed) Get(key string) (val []byte, err error) {
	return p.Store.Get(p.WithPrefix(key))
}

func (p *Prefixed) Remove(key string, val []byte) error {
	return p.Store.Remove(p.WithPrefix(key), val)
}

func (p *Prefixed) Delete(key string) error {
	return p.Store.Delete(p.WithPrefix(key))
}

func (p *Prefixed) Apply(conditions []Condition, mutations []Mutation) (bool, error) {
	checks := make([]Condition, len(conditions))
	for i, c := range conditions {
		checks[i] = c
		checks[i].Key = p.WithPrefix(c.Key)
	}
	ops := make([]Mutation, len(mutations))
	for i, m := range mutations {
		ops[i] = m
		ops[i].Key = p.WithPrefix(m.Key)
	}
	return p.Store.Apply(checks, ops)
}
