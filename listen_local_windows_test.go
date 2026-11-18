//go:build windows

package tunnel

import (
	"testing"
	"time"
)

func TestListenLocal(t *testing.T) {
	path := `\\.\pipe\ssh-agent-tunnel-test-` + t.Name()
	ln, err := ListenLocal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
			accepted <- struct{}{}
		}
	}()
	c, err := dialAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("accept timed out")
	}
	c.Close()
}
