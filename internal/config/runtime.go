// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

type serviceStopper struct {
	name string
	stop func(context.Context) error
}

// serviceRuntime owns listener errors and shutdown ordering. Listener failures
// are returned to the caller instead of terminating the process in a goroutine.
type serviceRuntime struct {
	ctx      context.Context
	errors   chan error
	stoppers []serviceStopper
	stopping atomic.Bool
}

func newServiceRuntime(ctx context.Context) *serviceRuntime {
	return &serviceRuntime{ctx: ctx, errors: make(chan error, 8)}
}

func (r *serviceRuntime) report(name string, err error) {
	if err == nil || r.stopping.Load() {
		return
	}
	select {
	case r.errors <- fmt.Errorf("%s service: %w", name, err):
	default:
		// Never block a service's cleanup when another failure is already
		// queued. Any one of these failures initiates the same graceful stop.
	}
}

func (r *serviceRuntime) addStopper(name string, stop func(context.Context) error) {
	r.stoppers = append(r.stoppers, serviceStopper{name: name, stop: stop})
}

// The caller binds PacketConn/Listener synchronously. Waiting for readiness
// removes the Server.Shutdown versus initial startup race in the DNS library.
func (r *serviceRuntime) startDNS(name string, server *dns.Server, extraClose func() error) error {
	ready, done := make(chan struct{}), make(chan struct{})
	var serveErr error
	server.NotifyStartedFunc = func() { close(ready) }
	r.addStopper(name, func(ctx context.Context) error {
		var err error
		select {
		case <-ready:
			err = server.ShutdownContext(ctx)
		case <-done:
			// Startup failed before NotifyStartedFunc could fire.
		case <-ctx.Done():
			err = ctx.Err()
		}
		// These closes are also needed when initialization failed before the
		// DNS server took ownership of its already-bound listener.
		if server.Listener != nil {
			server.Listener.Close()
		}
		if server.PacketConn != nil {
			server.PacketConn.Close()
		}
		if extraClose != nil {
			err = errors.Join(err, extraClose())
		}
		select {
		case <-done:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		}
		return err
	})
	go func() {
		serveErr = server.ActivateAndServe()
		r.report(name, serveErr)
		close(done)
	}()
	select {
	case <-ready:
		return nil
	case <-done:
		if serveErr == nil {
			serveErr = errors.New("stopped before becoming ready")
		}
		return fmt.Errorf("start %s listener: %w", name, serveErr)
	case <-r.ctx.Done():
		return r.ctx.Err()
	}
}

func (r *serviceRuntime) startHTTP(name string, listener net.Listener, server *http.Server) {
	done := make(chan struct{})
	r.addStopper(name, func(ctx context.Context) error {
		err := server.Shutdown(ctx)
		if err != nil {
			server.Close()
		}
		listener.Close()
		select {
		case <-done:
		case <-ctx.Done():
			err = errors.Join(err, ctx.Err())
		}
		return err
	})
	go func() {
		err := server.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			r.report(name, err)
		}
		close(done)
	}()
}

func (r *serviceRuntime) shutdown(ctx context.Context) error {
	r.stopping.Store(true)
	failures := make(chan error, len(r.stoppers))
	var wg sync.WaitGroup
	for _, stopper := range r.stoppers {
		wg.Go(func() {
			if err := stopper.stop(ctx); err != nil {
				failures <- fmt.Errorf("stop %s: %w", stopper.name, err)
			}
		})
	}
	wg.Wait()
	close(failures)
	var result error
	for err := range failures {
		result = errors.Join(result, err)
	}
	return result
}
