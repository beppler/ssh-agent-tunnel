//go:build windows

package tunnel

import (
	"net"

	"github.com/Microsoft/go-winio"
)

func dialAgent(path string) (net.Conn, error) { return winio.DialPipe(path, nil) }

func DefaultAgentPath() string { return `\\.\pipe\openssh-ssh-agent` }
