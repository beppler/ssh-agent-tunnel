package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"time"
)

const handshakeTimeout = 5 * time.Second

func serve(ln net.Listener, key []byte, agentPath string) {
	cert, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}
	ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
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
		go handleServerConn(c.(*tls.Conn), key, agentPath)
	}
}

func handleServerConn(c *tls.Conn, key []byte, agentPath string) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := handshake(c, key, true); err != nil {
		log.Printf("rejected %s: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	agent, err := dialAgent(agentPath)
	if err != nil {
		log.Printf("agent dial: %v", err)
		c.Close()
		return
	}
	relay(c, agent)
}
