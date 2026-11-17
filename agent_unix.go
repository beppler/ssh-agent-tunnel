//go:build !windows

package main

import (
	"net"
	"os"
)

func dialAgent(path string) (net.Conn, error) { return net.Dial("unix", path) }

func defaultAgentPath() string { return os.Getenv("SSH_AUTH_SOCK") }
