// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package ttlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

func testStores(t *testing.T, lim limits, fn func(*testing.T, TtlStore, TtlStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		store := &SimpleTtlStore{MaxSize: lim.MaxSize, MaxBytes: lim.MaxBytes, MaxValuesPerKey: lim.MaxValuesPerKey, MaxValueBytes: lim.MaxValueBytes}
		fn(t, store, store)
	})
	t.Run("valkey", func(t *testing.T) {
		addr := os.Getenv("DNSCHECK_TEST_VALKEY_ADDR")
		if addr == "" {
			t.Skip("set DNSCHECK_TEST_VALKEY_ADDR to an isolated local Valkey; test clears DB15")
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			t.Fatal("integration test requires an explicit loopback Valkey address")
		}
		makeClient := func() *ValkeyClient {
			client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, SelectDB: 15, ForceSingleClient: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			return &ValkeyClient{Client: client, MaxSize: lim.MaxSize, MaxBytes: lim.MaxBytes, MaxValuesPerKey: lim.MaxValuesPerKey, MaxValueBytes: lim.MaxValueBytes}
		}
		a, b := makeClient(), makeClient()
		if err := a.Do(context.Background(), a.B().Flushdb().Build()).Error(); err != nil {
			t.Fatal(err)
		}
		fn(t, a, b)
	})
}
func getValue(t *testing.T, store TtlStore, key string) []byte {
	t.Helper()
	v, e := store.Get(key)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestAtomicClaimAcrossIndependentClients(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, b TtlStore) {
		start := make(chan struct{})
		results := make(chan bool, 20)
		errs := make(chan error, 20)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				store := a
				if i%2 != 0 {
					store = b
				}
				owner := []byte(fmt.Sprintf("owner-%d", i))
				ok, err := store.Apply([]Condition{{Key: "name"}}, []Mutation{{Kind: SetValue, Key: "name", Value: owner, TTL: 60}, {Kind: SetValue, Key: "index:" + string(owner), Value: []byte("name"), TTL: 60}})
				results <- ok
				errs <- err
			}(i)
		}
		close(start)
		wg.Wait()
		close(results)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		winners := 0
		for ok := range results {
			if ok {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("got %d owners, want exactly one", winners)
		}
		keys, err := a.List("index:")
		if err != nil || len(keys) != 1 {
			t.Fatalf("orphan owner indexes: %v %v", keys, err)
		}
	})
}
func TestConditionalBatchDoesNotPartiallyApply(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, b TtlStore) {
		if err := a.Set("owner", []byte("old"), 60); err != nil {
			t.Fatal(err)
		}
		if err := b.Set("owner", []byte("revoked"), 60); err != nil {
			t.Fatal(err)
		}
		ok, err := a.Apply([]Condition{{Key: "owner", Value: []byte("old")}}, []Mutation{{Kind: SetValue, Key: "owner", Value: []byte("old"), TTL: 60}, {Kind: SetValue, Key: "address", Value: []byte("192.0.2.1"), TTL: 60}})
		if err != nil || ok {
			t.Fatalf("stale operation accepted: %v %v", ok, err)
		}
		if string(getValue(t, a, "owner")) != "revoked" || getValue(t, a, "address") != nil {
			t.Fatal("conditional batch partially applied")
		}
	})
}
func TestQuotaFailurePreservesPreviousData(t *testing.T) {
	testStores(t, limits{MaxSize: 2, MaxBytes: 100}, func(t *testing.T, a, b TtlStore) {
		for _, key := range []string{"one", "two"} {
			if err := a.Set(key, []byte("original"), 60); err != nil {
				t.Fatal(err)
			}
		}
		_, err := b.Apply(nil, []Mutation{{Kind: SetValue, Key: "one", Value: []byte("changed"), TTL: 60}, {Kind: SetValue, Key: "three", Value: []byte("new"), TTL: 60}})
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("expected capacity failure, got %v", err)
		}
		if string(getValue(t, a, "one")) != "original" || getValue(t, a, "three") != nil {
			t.Fatal("capacity error changed existing data")
		}
		if err := a.Set("one", bytes.Repeat([]byte("x"), 99), 60); !errors.Is(err, ErrCapacity) {
			t.Fatalf("byte quota not applied: %v", err)
		}
		if string(getValue(t, a, "one")) != "original" {
			t.Fatal("failed replacement deleted previous value")
		}
		if err := a.Delete("two"); err != nil {
			t.Fatal(err)
		}
		if err := a.Set("three", []byte("new"), 60); err != nil {
			t.Fatal(err)
		}
	})
}
func TestValuesAreIdempotentAndBounded(t *testing.T) {
	testStores(t, limits{MaxValuesPerKey: 2}, func(t *testing.T, a, b TtlStore) {
		for i := 0; i < 50; i++ {
			if err := a.Add("txt", []byte("same"), 60); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.Add("txt", []byte("other"), 60); err != nil {
			t.Fatal(err)
		}
		if err := b.Add("txt", []byte("third"), 60); !errors.Is(err, ErrCapacity) {
			t.Fatalf("per-key limit not applied: %v", err)
		}
		vals, err := a.Values("txt")
		if err != nil || len(vals) != 2 {
			t.Fatalf("duplicate accumulation: %d %v", len(vals), err)
		}
		if err := a.Remove("txt", []byte("same")); err != nil {
			t.Fatal(err)
		}
		vals, err = a.Values("txt")
		if err != nil || len(vals) != 1 || string(vals[0]) != "other" {
			t.Fatalf("remove damaged other values: %v %v", vals, err)
		}
	})
}
func TestValuesCannotAliasInternalState(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, _ TtlStore) {
		value := []byte("safe")
		if err := a.Set("key", value, 60); err != nil {
			t.Fatal(err)
		}
		value[0] = 'x'
		got := getValue(t, a, "key")
		got[0] = 'x'
		if string(getValue(t, a, "key")) != "safe" {
			t.Fatal("caller mutated stored state through a slice")
		}
	})
}
func TestQuotaReclaimedAfterExpiry(t *testing.T) {
	testStores(t, limits{MaxSize: 1}, func(t *testing.T, a, _ TtlStore) {
		if err := a.Set("old", []byte("expired"), 1); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for getValue(t, a, "old") != nil {
			if time.Now().After(deadline) {
				t.Fatal("TTL did not expire")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := a.Set("new", []byte("fresh"), 60); err != nil {
			t.Fatalf("expired record reserved quota: %v", err)
		}
	})
}
func TestSnapshotVersionLimitsAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.json")
	store := &SimpleTtlStore{}
	if err := store.Set("key", []byte("value"), 60); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteFile(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode %v", info.Mode().Perm())
	}
	loaded := &SimpleTtlStore{}
	if err := loaded.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if string(getValue(t, loaded, "key")) != "value" {
		t.Fatal("snapshot round trip failed")
	}
	if err := os.WriteFile(path, []byte(`{"legacy-key":[{"Expires":4294967295,"Value":"eA=="}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loaded.LoadFile(path); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("legacy snapshot accepted: %v", err)
	}
	if string(getValue(t, loaded, "key")) != "value" {
		t.Fatal("failed load replaced current state")
	}
	snap := snapshot{Version: 2, Records: map[string][]ValueWithExpiration{"a": {{Expires: uint32(time.Now().Unix() + 60), Value: []byte("long")}}}}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	small := &SimpleTtlStore{MaxBytes: 2}
	if err = small.LoadFile(path); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversize snapshot accepted: %v", err)
	}
}
func TestValkeyPreflightTypeErrorDoesNotWrite(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, _ TtlStore) {
		client, ok := a.(*ValkeyClient)
		if !ok {
			return
		}
		if err := a.Set("safe", []byte("original"), 60); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		// A corrupt/legacy key in a later mutation must fail before earlier writes.
		if err := client.Do(ctx, client.B().Hset().Key(physicalKey("bad")).FieldValue().FieldValue("legacy", "value").Build()).Error(); err != nil {
			t.Fatal(err)
		}
		_, err := a.Apply(nil, []Mutation{{Kind: SetValue, Key: "safe", Value: []byte("changed"), TTL: 60}, {Kind: SetValue, Key: "bad", Value: []byte("new"), TTL: 60}})
		if err == nil {
			t.Fatal("corrupt key was accepted")
		}
		if string(getValue(t, a, "safe")) != "original" {
			t.Fatal("script changed an earlier key before rejecting a later wrong type")
		}
	})
}

func TestValkeyStartupRejectsLegacyDatabase(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, _ TtlStore) {
		client, ok := a.(*ValkeyClient)
		if !ok {
			return
		}
		if err := client.CheckConfiguration(); err != nil {
			t.Fatalf("clean dedicated database rejected: %v", err)
		}
		if err := client.Do(context.Background(), client.B().Set().Key("legacy:registration").Value("legacy-data").Build()).Error(); err != nil {
			t.Fatal(err)
		}
		if err := client.CheckConfiguration(); !errors.Is(err, ErrLegacyFormat) {
			t.Fatalf("legacy database silently accepted: %v", err)
		}
	})
}

func TestInvalidExpirationCannotWrap(t *testing.T) {
	testStores(t, limits{}, func(t *testing.T, a, _ TtlStore) {
		if err := a.Set("key", []byte("value"), ^uint32(0)); !errors.Is(err, ErrInvalidOperation) {
			t.Fatalf("overflowing timestamp accepted: %v", err)
		}
		if getValue(t, a, "key") != nil {
			t.Fatal("invalid TTL mutated state")
		}
	})
}
