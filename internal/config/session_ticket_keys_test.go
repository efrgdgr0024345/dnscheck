// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTicketKeyManagerClosesConcurrentAddAndRotationWorker(t *testing.T) {
	m, err := NewSessionTicketKeyManager(filepath.Join(t.TempDir(), "ticket-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() { m.AddConfig(&tls.Config{}, "test") })
	}
	for range 4 {
		workers.Go(func() { _ = m.Close() })
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("ticket key manager did not close with concurrent callers")
	}
	select {
	case <-m.done:
	default:
		t.Fatal("Close returned before worker exited")
	}
	m.AddConfig(&tls.Config{}, "after-close")
}

func TestTicketKeySaveIsPrivateAndReloadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ticket-keys.json")
	m := &SessionTicketKeyManager{file: path}
	m.addNewKey()
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key file permissions: %v", err)
	}
	loaded := &SessionTicketKeyManager{file: path}
	if err := loaded.load(); err != nil {
		t.Fatal(err)
	}
	if len(loaded.keys) != 1 || loaded.keys[0].Key != m.keys[0].Key {
		t.Fatal("saved key did not survive reload")
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("temporary key files left behind: %v", err)
	}
}

func TestInvalidTicketKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ticket-keys.json")
	m := &SessionTicketKeyManager{file: path, keys: []ticketKey{{Created: time.Now()}}}
	if err := m.save(); err != nil {
		t.Fatal(err)
	}
	if err := m.load(); err == nil {
		t.Fatal("all-zero key accepted")
	}
}
