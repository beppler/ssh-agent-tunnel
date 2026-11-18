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
	Key       []byte
	AgentPath string       // unix socket or Windows named pipe
	Logger    *slog.Logger // nil = discard
}

// Serve accepts connections on ln until ctx is cancelled. It returns nil on
// context cancellation and closes the listener plus every in-flight connection.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	cert, err := selfSignedCert()
	if err != nil {
		return err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	return acceptLoop(ctx, ln, discardIfNil(s.Logger), func(ctx context.Context, c net.Conn) {
		s.handle(ctx, tls.Server(c, cfg))
	})
}

func (s *Server) handle(ctx context.Context, c *tls.Conn) {
	log := discardIfNil(s.Logger)
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := handshake(c, s.Key, true); err != nil {
		log.Warn("rejected", "addr", c.RemoteAddr(), "err", err)
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	agent, err := dialAgent(s.AgentPath)
	if err != nil {
		log.Error("agent dial", "err", err)
		c.Close()
		return
	}
	relay(ctx, c, agent)
}
