package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	macSize    = sha256.Size
	minKeySize = 32
	KeyEnv     = "SSH_AGENT_TUNNEL_KEY"
	// ProtocolVersion is the wire-protocol marker; it is also the MAC context
	// and the TLS keying-material label.
	ProtocolVersion = "ssh-agent-tunnel/v2"
)

// computeMAC binds the shared key to one TLS session (ekm) and a role, so a
// MITM terminating TLS on each leg, or a reflected MAC, fails verification.
func computeMAC(key []byte, role string, ekm []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(ProtocolVersion))
	h.Write([]byte(role))
	h.Write(ekm)
	return h.Sum(nil)
}

func verifyMAC(key []byte, role string, ekm, got []byte) bool {
	return hmac.Equal(computeMAC(key, role, ekm), got)
}

// selfSignedCert makes an ephemeral cert; it is never verified, the HMAC authenticates the peer.
func selfSignedCert() (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ssh-agent-tunnel"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

// handshake runs TLS, then mutual HMAC proof over the session's exported keying material.
// The client proves first: a server that sent its proof first would give any peer a free offline key-guessing oracle.
func handshake(c *tls.Conn, key []byte, isServer bool) error {
	if err := c.Handshake(); err != nil {
		return err
	}
	st := c.ConnectionState()
	ekm, err := st.ExportKeyingMaterial(ProtocolVersion, nil, 32)
	if err != nil {
		return err
	}
	send := func(role string) error {
		_, err := c.Write(computeMAC(key, role, ekm))
		return err
	}
	recv := func(role string) error {
		got := make([]byte, macSize)
		if _, err := io.ReadFull(c, got); err != nil {
			return err
		}
		if !verifyMAC(key, role, ekm, got) {
			return errors.New("bad MAC")
		}
		return nil
	}
	if isServer {
		if err := recv("client"); err != nil {
			return err
		}
		return send("server")
	}
	if err := send("client"); err != nil {
		return err
	}
	return recv("server")
}

// LoadKey reads the shared key from path, or from $SSH_AGENT_TUNNEL_KEY if path is empty.
func LoadKey(path string) ([]byte, error) {
	var key string
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		key = string(b)
	} else {
		key = os.Getenv(KeyEnv)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("no key: use -key-file or %s", KeyEnv)
	}
	if len(key) < minKeySize {
		return nil, errors.New("key must be at least 32 bytes")
	}
	return []byte(key), nil
}

// NewKey returns a fresh 32-byte key, base64-encoded, suitable for
// SSH_AGENT_TUNNEL_KEY or a key file.
func NewKey() string {
	b := make([]byte, minKeySize)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.StdEncoding.EncodeToString(b)
}
