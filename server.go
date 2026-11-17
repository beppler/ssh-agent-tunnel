package main

import (
	"errors"
	"io"
	"log"
	"net"
	"time"
)

const handshakeTimeout = 5 * time.Second

func serve(ln net.Listener, key []byte, agentPath string) {
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
		go handleServerConn(c, key, agentPath)
	}
}

func handleServerConn(c net.Conn, key []byte, agentPath string) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	challenge, err := newChallenge()
	if err == nil {
		_, err = c.Write(challenge)
	}
	got := make([]byte, 32)
	if err == nil {
		_, err = io.ReadFull(c, got)
	}
	if err != nil || !verifyMAC(key, challenge, got) {
		log.Printf("rejected %s", c.RemoteAddr())
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
