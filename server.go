package tunnel

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"time"
)

// Server accepts tunnel connections and relays them to a local ssh-agent.
type Server struct {
	Key            []byte
	AgentPath      string       // unix socket or Windows named pipe
	Logger         *slog.Logger // nil = discard
	HandshakeLimit int          // max unauthenticated handshakes at once; <=0 = default (64)
}

// handshakeLimit caps how many connections may sit in the unauthenticated
// handshake at once; established agent sessions do not count against it.
const handshakeLimit = 64

// Serve accepts connections on ln until ctx is cancelled. It returns nil on
// context cancellation and closes the listener plus every in-flight connection.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	limit := s.HandshakeLimit
	if limit <= 0 {
		limit = handshakeLimit
	}
	sem := make(chan struct{}, limit)
	return acceptLoop(ctx, ln, discardIfNil(s.Logger), func(ctx context.Context, c net.Conn) {
		tlsConn := tls.Server(c, cfg)
		select {
		case sem <- struct{}{}:
		default:
			c.Close() // limit reached: drop silently so peers cannot flood the log
			return
		}
		authenticated := s.auth(tlsConn)
		<-sem
		if !authenticated {
			return
		}
		agent, err := dialAgent(s.AgentPath)
		if err != nil {
			discardIfNil(s.Logger).Error("agent dial", "err", err)
			tlsConn.Close()
			return
		}
		relay(ctx, tlsConn, agent)
	})
}

// auth runs the TLS+HMAC handshake; on failure it closes the connection and returns false.
func (s *Server) auth(c *tls.Conn) bool {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := handshake(c, s.Key, true); err != nil {
		discardIfNil(s.Logger).Warn("rejected", "addr", c.RemoteAddr(), "err", err)
		c.Close()
		return false
	}
	c.SetDeadline(time.Time{})
	return true
}
