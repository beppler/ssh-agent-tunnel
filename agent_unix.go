//go:build !windows

package tunnel

import (
	"net"
	"os"
)

func dialAgent(path string) (net.Conn, error) { return net.Dial("unix", path) }

func DefaultAgentPath() string { return os.Getenv("SSH_AUTH_SOCK") }

func ListenLocal(path string) (net.Listener, error) { return ListenUnix(path) }

func DefaultSocketPath() string { return "/run/ssh-agent.sock" }
