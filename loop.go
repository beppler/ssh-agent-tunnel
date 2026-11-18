package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

const handshakeTimeout = 5 * time.Second

// acceptLoop runs the shared accept/shutdown machinery: accept until ctx is
// cancelled or the listener is closed, handle each connection in a goroutine,
// and on cancel close the listener and every in-flight connection before
// waiting for the handlers. Returns nil on context cancellation.
func acceptLoop(ctx context.Context, ln net.Listener, log *slog.Logger, handle func(context.Context, net.Conn)) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	add := func(c net.Conn) { mu.Lock(); conns[c] = struct{}{}; mu.Unlock() }
	remove := func(c net.Conn) { mu.Lock(); delete(conns, c); mu.Unlock() }
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			ln.Close()
			mu.Lock()
			for c := range conns {
				c.Close()
			}
			mu.Unlock()
		case <-done:
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			// stopping: wait for handlers; a caller-closed listener returns
			// at once and leaves its handlers running
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Error("accept", "err", err)
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		add(c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer remove(c)
			handle(ctx, c)
		}()
	}
}

// discardIfNil gives handlers a logger that writes nowhere when the user left the field empty.
func discardIfNil(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.New(slog.DiscardHandler)
	}
	return l
}
