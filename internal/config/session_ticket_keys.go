// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

const (
	TicketKeyLifetime = 7 * 24 * time.Hour
	TicketKeyRotation = 24 * time.Hour
)

type ticketKey struct {
	Key     [32]byte
	Created time.Time
}

type tlsConfig struct {
	*tls.Config
	info string
}

type SessionTicketKeyManager struct {
	file      string
	keys      []ticketKey
	configs   []tlsConfig
	add       chan tlsConfig
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func NewSessionTicketKeyManager(file string) (*SessionTicketKeyManager, error) {
	m := &SessionTicketKeyManager{
		file: file,
		add:  make(chan tlsConfig),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if err := m.load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	m.prune()
	if len(m.keys) == 0 {
		m.addNewKey()
		if err := m.save(); err != nil {
			return nil, err
		}
	}
	go func() {
		defer close(m.done)
		rotate := time.NewTimer(time.Until(m.keys[0].Created.Add(TicketKeyRotation)))
		defer rotate.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-rotate.C:
				previous := append([]ticketKey(nil), m.keys...)
				m.addNewKey()
				m.prune()
				if err := m.save(); err != nil {
					m.keys = previous
					log.Printf("[error] TLS ticket-key rotation could not be persisted; will retry: %v", err)
					rotate.Reset(time.Minute)
					continue
				}
				m.setAllConfigKeys()
				rotate.Reset(time.Until(m.keys[0].Created.Add(TicketKeyRotation)))
			case c := <-m.add:
				m.configs = append(m.configs, c)
				m.setConfigKeys(c)
			}
		}
	}()
	return m, nil
}

func (m *SessionTicketKeyManager) AddConfig(conf *tls.Config, info string) {
	if conf == nil {
		return
	}
	select {
	case <-m.stop:
	case m.add <- tlsConfig{conf, info}:
	}
}

// Close stops rotation and waits for its worker to exit. It is safe to call
// concurrently or more than once, including while a config is being added.
func (m *SessionTicketKeyManager) Close() error {
	if m == nil || m.stop == nil {
		return nil
	}
	m.closeOnce.Do(func() { close(m.stop) })
	<-m.done
	return nil
}

func (m *SessionTicketKeyManager) load() error {
	f, err := os.Open(m.file)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("TLS ticket keys require a private regular file (mode 0600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if err != nil {
		return err
	}
	if len(b) > 16<<10 {
		return errors.New("TLS ticket-key file is too large")
	}
	if err := json.Unmarshal(b, &m.keys); err != nil {
		return err
	}
	if len(m.keys) > 16 {
		return errors.New("too many persisted TLS ticket keys")
	}
	for _, k := range m.keys {
		if k.Key == [32]byte{} || k.Created.IsZero() || k.Created.After(time.Now().Add(5*time.Minute)) {
			return errors.New("invalid persisted TLS ticket key")
		}
	}
	slices.SortFunc(m.keys, func(a, b ticketKey) int { return b.Created.Compare(a.Created) })
	return nil
}

func (m *SessionTicketKeyManager) save() error {
	b, err := json.Marshal(m.keys, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.file)
	f, err := os.CreateTemp(dir, ".ticket-keys-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, m.file); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (m *SessionTicketKeyManager) addNewKey() {
	var newKey [32]byte
	rand.Read(newKey[:])
	m.keys = slices.Insert(m.keys, 0, ticketKey{newKey, time.Now()})
}

func (m *SessionTicketKeyManager) prune() {
	m.keys = slices.DeleteFunc(m.keys, func(k ticketKey) bool {
		return time.Since(k.Created) >= TicketKeyLifetime
	})
}

func (m *SessionTicketKeyManager) setAllConfigKeys() {
	for _, c := range m.configs {
		m.setConfigKeys(c)
	}
}

func (m *SessionTicketKeyManager) setConfigKeys(c tlsConfig) {
	keys := make([][32]byte, len(m.keys))
	for i, k := range m.keys {
		b, err := hkdf.Key(sha256.New, k.Key[:], nil, c.info, 32)
		if err != nil {
			panic(err)
		}
		keys[i] = [32]byte(b)
	}
	c.SetSessionTicketKeys(keys)
}
