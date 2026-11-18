//go:build windows

package tunnel

import (
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func dialAgent(path string) (net.Conn, error) { return winio.DialPipe(path, nil) }

func DefaultAgentPath() string { return `\\.\pipe\openssh-ssh-agent` }

// ListenLocal creates a Windows named pipe at path, with an explicit SDDL so
// access is only SYSTEM, Administrators and the current user, never whatever
// default DACL the token carries.
func ListenLocal(path string) (net.Listener, error) {
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + u.User.Sid.String() + ")"
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
}

func DefaultSocketPath() string { return `\\.\pipe\ssh-agent-tunnel` }
