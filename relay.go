package tunnel

import (
	"context"
	"io"
	"net"
)

type closeWriter interface{ CloseWrite() error }

// relay copies both directions until both finish, then closes both conns.
// When ctx is cancelled it closes both conns so pending copies unblock and
// relay returns promptly.
func relay(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	select {
	case <-done:
	case <-ctx.Done():
	}
	if ctx.Err() != nil {
		a.Close()
		b.Close()
	}
	<-done
	<-done
	a.Close()
	b.Close()
}
