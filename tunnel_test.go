//go:build !windows

package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

// setup starts a fake echo agent, a server and a client; returns client socket path and agent-conn counter.
func setup(t *testing.T, clientKey []byte) (string, chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent.sock")
	aln, err := net.Listen("unix", agentPath)
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan struct{}, 10)
	go func() {
		for {
			c, err := aln.Accept()
			if err != nil {
				return
			}
			conns <- struct{}{}
			go func() { buf := make([]byte, 64); n, _ := c.Read(buf); c.Write(buf[:n]); c.Close() }()
		}
	}()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	go serve(sln, testKey, agentPath)
	sock := filepath.Join(dir, "client.sock")
	cln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	go runClient(cln, clientKey, sln.Addr().String())
	t.Cleanup(func() { aln.Close(); sln.Close(); cln.Close() })
	return sock, conns
}

func TestEndToEnd(t *testing.T) {
	sock, _ := setup(t, testKey)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := c.Read(buf); err != nil || string(buf) != "hello" {
		t.Fatalf("got %q err %v", buf, err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	sock, conns := setup(t, []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
	c, _ := net.Dial("unix", sock)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	// the client now fails its handshake before reading, so the close may surface as EOF or a reset
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("want closed conn, got n=%d err=%v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection left open")
	}
	select {
	case <-conns:
		t.Fatal("agent was contacted")
	default:
	}
}

func TestHandshakeTimeout(t *testing.T) {
	dir := t.TempDir()
	aln, _ := net.Listen("unix", filepath.Join(dir, "a.sock"))
	defer aln.Close()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	go serve(sln, testKey, filepath.Join(dir, "a.sock"))
	c, _ := net.Dial("tcp", sln.Addr().String())
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout + 3*time.Second))
	// send nothing; the server must drop the stalled TLS handshake
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected close")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server did not drop stalled handshake")
	}
}

func TestPlaintextClientRejected(t *testing.T) {
	dir := t.TempDir()
	aln, _ := net.Listen("unix", filepath.Join(dir, "a.sock"))
	defer aln.Close()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	go serve(sln, testKey, filepath.Join(dir, "a.sock"))
	c, _ := net.Dial("tcp", sln.Addr().String())
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(make([]byte, 64)) // not a TLS ClientHello
	buf := make([]byte, 1024)
	for {
		if _, err := c.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("server kept plaintext connection open")
			}
			return
		}
	}
}

// A server that doesn't know the key must be rejected by the client.
func TestWrongServerKeyRejected(t *testing.T) {
	cert, _ := selfSignedCert()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	go func() {
		c, err := sln.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		tc.SetDeadline(time.Now().Add(2 * time.Second))
		handshake(tc, []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"), true)
		tc.Close()
	}()
	c, _ := net.Dial("tcp", sln.Addr().String())
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := handshake(tc, testKey, false); err == nil {
		t.Fatal("client accepted server with wrong key")
	}
}

func TestTrafficEncrypted(t *testing.T) {
	dir := t.TempDir()
	agentPath := filepath.Join(dir, "agent.sock")
	aln, _ := net.Listen("unix", agentPath)
	defer aln.Close()
	go func() {
		c, err := aln.Accept()
		if err == nil {
			buf := make([]byte, 64)
			n, _ := c.Read(buf)
			c.Write(buf[:n])
			c.Close()
		}
	}()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	go serve(sln, testKey, agentPath)
	// tap: client -> tap -> server, recording bytes
	tap, _ := net.Listen("tcp", "127.0.0.1:0")
	defer tap.Close()
	var mu sync.Mutex
	var seen []byte
	go func() {
		c, err := tap.Accept()
		if err != nil {
			return
		}
		s, _ := net.Dial("tcp", sln.Addr().String())
		go io.Copy(c, s)
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			mu.Lock()
			seen = append(seen, buf[:n]...)
			mu.Unlock()
			s.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	cln, _ := listenUnix(filepath.Join(dir, "c.sock"))
	defer cln.Close()
	go runClient(cln, testKey, tap.Addr().String())
	c, _ := net.Dial("unix", filepath.Join(dir, "c.sock"))
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	secret := "SECRET-AGENT-PAYLOAD"
	c.Write([]byte(secret))
	buf := make([]byte, len(secret))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != secret {
		t.Fatalf("got %q err %v", buf, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 || bytes.Contains(seen, []byte(secret)) {
		t.Fatalf("payload visible on the wire (seen %d bytes)", len(seen))
	}
}

func TestListenUnixRefusesRegularFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "precious")
	os.WriteFile(f, []byte("x"), 0o600)
	if _, err := listenUnix(f); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatal("file was removed")
	}
}

// The server must not send anything before the client proves the key (offline-guessing oracle).
func TestServerSilentUntilClientProves(t *testing.T) {
	dir := t.TempDir()
	sln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer sln.Close()
	go serve(sln, testKey, filepath.Join(dir, "a.sock"))
	c, _ := net.Dial("tcp", sln.Addr().String())
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if n, err := tc.Read(make([]byte, 1)); n != 0 {
		t.Fatalf("server sent %d bytes before client proof (err %v)", n, err)
	}
}

// A proof captured from one TLS session must not verify in another.
func TestProofNotReplayableAcrossSessions(t *testing.T) {
	cert, _ := selfSignedCert()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	ccfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
	// pair opens a connected, handshaken TLS pair and returns both ends.
	pair := func() (cli, srv *tls.Conn) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		b, _ := net.Dial("tcp", ln.Addr().String())
		a, _ := ln.Accept()
		srv, cli = tls.Server(a, cfg), tls.Client(b, ccfg)
		errc := make(chan error, 1)
		go func() { errc <- srv.Handshake() }()
		if err := cli.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		return
	}
	ekm := func(c *tls.Conn) []byte {
		st := c.ConnectionState()
		e, err := st.ExportKeyingMaterial(macContext, nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	cli1, srv1 := pair()
	cli2, srv2 := pair()
	defer func() { cli1.Close(); srv1.Close(); cli2.Close(); srv2.Close() }()
	proof := computeMAC(testKey, "client", ekm(cli1))
	if !verifyMAC(testKey, "client", ekm(srv1), proof) {
		t.Fatal("proof rejected in its own session")
	}
	if verifyMAC(testKey, "client", ekm(srv2), proof) {
		t.Fatal("proof accepted in another session")
	}
}
