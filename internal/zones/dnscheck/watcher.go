// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package dnscheck

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/miekg/dns"
)

var (
	ErrWatcherExists   = errors.New("watcher already exists")
	ErrWatcherCapacity = errors.New("watcher capacity reached")
)

type Watcher interface {
	Send(req *dns.Msg, proto string, remoteAddr net.Addr, connState *tls.ConnectionState)
}

type WatcherHub interface {
	Get(watcherID string) Watcher
	// Register atomically claims an unused ID. The returned release function is
	// bound to this registration and cannot remove a later owner of the ID.
	Register(watcherID string, watcher Watcher) (release func(), err error)
}

type watcherRegistration struct{ watcher Watcher }

type SimpleWatcherHub struct {
	MaxSize int
	m       map[string]*watcherRegistration
	mu      sync.RWMutex
}

func (s *SimpleWatcherHub) Get(watcherID string) Watcher {
	s.mu.RLock()
	registration := s.m[watcherID]
	s.mu.RUnlock()
	if registration == nil {
		return nil
	}
	return registration.watcher
}

func (s *SimpleWatcherHub) Register(watcherID string, watcher Watcher) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[watcherID]; exists {
		return nil, ErrWatcherExists
	}
	if s.MaxSize > 0 && len(s.m) >= s.MaxSize {
		return nil, ErrWatcherCapacity
	}
	if s.m == nil {
		s.m = make(map[string]*watcherRegistration)
	}
	registration := &watcherRegistration{watcher: watcher}
	s.m[watcherID] = registration
	return func() {
		s.mu.Lock()
		if s.m[watcherID] == registration {
			delete(s.m, watcherID)
		}
		s.mu.Unlock()
	}, nil
}

func (s *SimpleWatcherHub) Size() int {
	s.mu.RLock()
	size := len(s.m)
	s.mu.RUnlock()
	return size
}
