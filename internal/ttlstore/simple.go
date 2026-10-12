// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package ttlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ValueWithExpiration struct {
	Expires uint32
	Value   []byte
}

// SimpleTtlStore has finite limits even when constructed with zero values.
// MaxSize counts values; MaxBytes counts logical key/value bytes, not all Go
// allocation overhead. Configure limits before the store is used concurrently.
type SimpleTtlStore struct {
	MaxSize         int
	MaxBytes        int
	MaxValuesPerKey int
	MaxValueBytes   int
	mu              sync.RWMutex
	saveMu          sync.Mutex
	m               map[string][]ValueWithExpiration
	size            int
	bytes           int
	dirty           bool
	revision        uint64
}

func (s *SimpleTtlStore) limits() limits {
	return normalizedLimits(s.MaxSize, s.MaxBytes, s.MaxValuesPerKey, s.MaxValueBytes)
}

func liveValues(rs []ValueWithExpiration, now uint32) []ValueWithExpiration {
	out := make([]ValueWithExpiration, 0, len(rs))
	for _, r := range rs {
		if r.Expires > now {
			out = append(out, ValueWithExpiration{r.Expires, bytes.Clone(r.Value)})
		}
	}
	return out
}

func valueBytes(key string, rs []ValueWithExpiration) int {
	n := 0
	for _, r := range rs {
		n += len(key) + len(r.Value)
	}
	return n
}

func (s *SimpleTtlStore) changed() { s.dirty = true; s.revision++ }

func (s *SimpleTtlStore) pruneLocked(now uint32) {
	for key, old := range s.m {
		live := old[:0]
		for _, r := range old {
			if r.Expires > now {
				live = append(live, r)
			} else {
				s.size--
				s.bytes -= len(key) + len(r.Value)
				s.changed()
			}
		}
		if len(live) == 0 {
			delete(s.m, key)
		} else {
			s.m[key] = live
		}
	}
}

func (s *SimpleTtlStore) Apply(checks []Condition, ops []Mutation) (bool, error) {
	lim := s.limits()
	if err := validateBatch(checks, ops, lim); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := uint32(time.Now().Unix())
	for _, c := range checks {
		live := liveValues(s.m[c.Key], now)
		if c.Value == nil {
			if len(live) != 0 {
				return false, nil
			}
		} else if len(live) != 1 || !bytes.Equal(live[0].Value, c.Value) {
			return false, nil
		}
	}
	// Stage every affected key before changing state. A capacity failure cannot
	// delete a previous value or leave half a registration behind.
	pending := make(map[string][]ValueWithExpiration)
	for _, op := range ops {
		rs, loaded := pending[op.Key]
		if !loaded {
			rs = liveValues(s.m[op.Key], now)
		}
		switch op.Kind {
		case DeleteKey:
			rs = nil
		case SetValue:
			rs = []ValueWithExpiration{{now + op.TTL, bytes.Clone(op.Value)}}
		case AddValue:
			found := false
			for i := range rs {
				if bytes.Equal(rs[i].Value, op.Value) {
					rs[i].Expires = now + op.TTL
					found = true
					break
				}
			}
			if !found {
				rs = append(rs, ValueWithExpiration{now + op.TTL, bytes.Clone(op.Value)})
			}
		case RemoveValue:
			out := rs[:0]
			for _, r := range rs {
				if !bytes.Equal(r.Value, op.Value) {
					out = append(out, r)
				}
			}
			rs = out
		}
		cap := lim.MaxValuesPerKey
		if op.MaxValues > 0 && op.MaxValues < cap {
			cap = op.MaxValues
		}
		if len(rs) > cap {
			return false, ErrCapacity
		}
		pending[op.Key] = rs
	}
	size, sizeBytes := s.size, s.bytes
	for key, rs := range pending {
		size += len(rs) - len(s.m[key])
		sizeBytes += valueBytes(key, rs) - valueBytes(key, s.m[key])
	}
	if size > lim.MaxSize || sizeBytes > lim.MaxBytes {
		// Pruning removes only already invisible records; mutations remain staged.
		s.pruneLocked(now)
		size, sizeBytes = s.size, s.bytes
		for key, rs := range pending {
			size += len(rs) - len(s.m[key])
			sizeBytes += valueBytes(key, rs) - valueBytes(key, s.m[key])
		}
		if size > lim.MaxSize || sizeBytes > lim.MaxBytes {
			return false, ErrCapacity
		}
	}
	if s.m == nil {
		s.m = make(map[string][]ValueWithExpiration)
	}
	for key, rs := range pending {
		if len(rs) == 0 {
			delete(s.m, key)
		} else {
			s.m[key] = rs
		}
	}
	if len(pending) > 0 {
		s.size, s.bytes = size, sizeBytes
		s.changed()
	}
	return true, nil
}

func (s *SimpleTtlStore) Add(key string, val []byte, ttl uint32) error {
	_, err := s.Apply(nil, []Mutation{{Kind: AddValue, Key: key, Value: val, TTL: ttl}})
	return err
}
func (s *SimpleTtlStore) Set(key string, val []byte, ttl uint32) error {
	_, err := s.Apply(nil, []Mutation{{Kind: SetValue, Key: key, Value: val, TTL: ttl}})
	return err
}
func (s *SimpleTtlStore) Remove(key string, val []byte) error {
	_, err := s.Apply(nil, []Mutation{{Kind: RemoveValue, Key: key, Value: val}})
	return err
}
func (s *SimpleTtlStore) Delete(key string) error {
	_, err := s.Apply(nil, []Mutation{{Kind: DeleteKey, Key: key}})
	return err
}
func (s *SimpleTtlStore) List(prefix string) (keys []string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint32(time.Now().Unix())
	for key, rs := range s.m {
		if strings.HasPrefix(key, prefix) {
			for _, r := range rs {
				if r.Expires > now {
					keys = append(keys, key)
					break
				}
			}
		}
	}
	sort.Strings(keys)
	return
}
func (s *SimpleTtlStore) Exists(key string) (bool, error) { v, err := s.Get(key); return v != nil, err }
func (s *SimpleTtlStore) Values(key string) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var vals [][]byte
	now := uint32(time.Now().Unix())
	for _, r := range s.m[key] {
		if r.Expires > now {
			vals = append(vals, bytes.Clone(r.Value))
		}
	}
	return vals, nil
}
func (s *SimpleTtlStore) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint32(time.Now().Unix())
	for _, r := range s.m[key] {
		if r.Expires > now {
			return bytes.Clone(r.Value), nil
		}
	}
	return nil, nil
}
func (s *SimpleTtlStore) Size() int { s.mu.RLock(); defer s.mu.RUnlock(); return s.size }
func (s *SimpleTtlStore) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(uint32(time.Now().Unix()))
}
func (s *SimpleTtlStore) PrunePeriodically(interval time.Duration) {
	for {
		time.Sleep(interval)
		s.Prune()
	}
}

type snapshot struct {
	Version int                              `json:"version"`
	Records map[string][]ValueWithExpiration `json:"records"`
}

// WriteFile copies state while locked, then encodes and fsyncs outside the data
// lock. Concurrent writes remain dirty for the next snapshot. Saves serialize
// so an older snapshot cannot replace a newer one.
func (s *SimpleTtlStore) WriteFile(path string) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.RLock()
	revision := s.revision
	copyMap := make(map[string][]ValueWithExpiration, len(s.m))
	now := uint32(time.Now().Unix())
	for key, rs := range s.m {
		copyMap[key] = liveValues(rs, now)
	}
	s.mu.RUnlock()
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+file+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(snapshot{Version: 2, Records: copyMap})
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.revision == revision {
		s.dirty = false
	}
	s.mu.Unlock()
	return nil
}
func (s *SimpleTtlStore) WriteFilePeriodically(path string, interval time.Duration) error {
	for {
		time.Sleep(interval)
		s.mu.RLock()
		dirty := s.dirty
		s.mu.RUnlock()
		if dirty {
			if err := s.WriteFile(path); err != nil {
				return err
			}
		}
	}
}
func (s *SimpleTtlStore) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	lim := s.limits()
	// Bound input before decoding; base64 and JSON have overhead beyond the
	// logical record budget. Reject truncation rather than accepting a prefix.
	fileLimit := int64(lim.MaxBytes)*3 + int64(lim.MaxSize)*128
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > fileLimit {
		return ErrCapacity
	}
	var snap snapshot
	dec := json.NewDecoder(io.LimitReader(f, fileLimit+1))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&snap); err != nil {
		return fmt.Errorf("%w: %v", ErrLegacyFormat, err)
	}
	if snap.Version != 2 {
		return ErrLegacyFormat
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid snapshot trailing data")
	}
	size, sizeBytes := 0, 0
	clean := make(map[string][]ValueWithExpiration)
	now := uint32(time.Now().Unix())
	for key, rs := range snap.Records {
		if len(key) == 0 || len(key) > MaxKeyBytes || len(rs) > lim.MaxValuesPerKey {
			return ErrCapacity
		}
		seen := make(map[string]bool)
		for _, r := range rs {
			if len(r.Value) > lim.MaxValueBytes || r.Value == nil {
				return ErrCapacity
			}
			if r.Expires <= now {
				continue
			}
			if seen[string(r.Value)] {
				return fmt.Errorf("invalid snapshot duplicate value")
			}
			seen[string(r.Value)] = true
			clean[key] = append(clean[key], r)
			size++
			sizeBytes += len(key) + len(r.Value)
		}
	}
	if size > lim.MaxSize || sizeBytes > lim.MaxBytes {
		return ErrCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = clean
	s.size = size
	s.bytes = sizeBytes
	s.revision++
	s.dirty = false
	return nil
}
