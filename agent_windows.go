//go:build windows

package main

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func dialAgent(path string) (net.Conn, error) { return winio.DialPipe(path, nil) }

func defaultAgentPath() string { return `\\.\pipe\openssh-ssh-agent` }
