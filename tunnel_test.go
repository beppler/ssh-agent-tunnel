//go:build !windows

package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
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
	if n, err := c.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("want clean EOF, got n=%d err=%v", n, err)
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
	buf := make([]byte, challengeSize)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	// stall; server must close
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected close")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server did not drop stalled handshake")
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
