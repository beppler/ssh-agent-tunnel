package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

// Client listens on ln (typically a unix socket) and relays each connection
// to a remote ssh-agent-tunnel server.
type Client struct {
	Key        []byte
	ServerAddr string
	Logger     *slog.Logger // nil = discard
}

// Serve accepts connections on ln until ctx is cancelled. It returns nil on
// context cancellation and closes the listener plus every in-flight connection.
func (c *Client) Serve(ctx context.Context, ln net.Listener) error {
	return acceptLoop(ctx, ln, discardIfNil(c.Logger), c.handle)
}

func (c *Client) handle(ctx context.Context, conn net.Conn) {
	log := discardIfNil(c.Logger)
	t, err := net.DialTimeout("tcp", c.ServerAddr, handshakeTimeout)
	if err != nil {
		log.Error("dial server", "err", err)
		conn.Close()
		return
	}
	t.SetDeadline(time.Now().Add(handshakeTimeout))
	tc := tls.Client(t, &tls.Config{
		MinVersion: tls.VersionTLS13,
		// the cert is not trusted; handshake() authenticates the server via the HMAC
		InsecureSkipVerify: true,
	})
	if err = handshake(tc, c.Key, false); err != nil {
		log.Error("handshake", "err", err)
		tc.Close()
		conn.Close()
		return
	}
	tc.SetDeadline(time.Time{})
	relay(ctx, conn, tc)
}

// ListenUnix creates a unix socket at path, replacing a stale socket but
// never any other kind of file.
func ListenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return ln, os.Chmod(path, 0o600)
}
