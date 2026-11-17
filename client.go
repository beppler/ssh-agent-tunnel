package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func listenUnix(path string) (net.Listener, error) {
	// remove a stale socket, but never any other kind of file
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

func runClient(ln net.Listener, key []byte, server string) {
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handleClientConn(c, key, server)
	}
}

func handleClientConn(c net.Conn, key []byte, server string) {
	t, err := net.DialTimeout("tcp", server, handshakeTimeout)
	if err != nil {
		log.Printf("dial server: %v", err)
		c.Close()
		return
	}
	t.SetDeadline(time.Now().Add(handshakeTimeout))
	tc := tls.Client(t, &tls.Config{
		MinVersion: tls.VersionTLS13,
		// the cert is not trusted; handshake() authenticates the server via the HMAC
		InsecureSkipVerify: true,
	})
	if err = handshake(tc, key, false); err != nil {
		log.Printf("handshake: %v", err)
		tc.Close()
		c.Close()
		return
	}
	tc.SetDeadline(time.Time{})
	relay(c, tc)
}
