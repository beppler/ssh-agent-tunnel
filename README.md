# ssh-agent-tunnel

Use the host's ssh-agent from a container over TCP, without mounting its socket.

- **server** (host): listens on TCP, authenticates each connection with an HMAC-SHA256 challenge-response, then relays to the local agent (unix socket, or the Windows OpenSSH named pipe `\\.\pipe\openssh-ssh-agent`).
- **client** (container, Linux): creates a unix socket to use as `SSH_AUTH_SOCK` and forwards each connection to the server.

```
# key: any secret of >= 32 bytes, shared by both sides (or set SSH_AGENT_TUNNEL_KEY)
head -c 32 /dev/urandom | base64 > tunnel.key

# host
ssh-agent-tunnel server -listen 0.0.0.0:7722 -key-file tunnel.key   # -agent defaults to $SSH_AUTH_SOCK

# container
ssh-agent-tunnel client -server host.docker.internal:7722 -socket /run/ssh-agent.sock -key-file tunnel.key
export SSH_AUTH_SOCK=/run/ssh-agent.sock
```

Protocol: the connection is TLS 1.3 (ephemeral self-signed server cert, not verified). Inside it, each side proves it knows the shared key with `HMAC-SHA256(key, "ssh-agent-tunnel/v2" || role || ekm)`, where `ekm` is exported keying material unique to that TLS session. The client proves first and the server answers only after checking it in constant time (5s timeout), so an unauthenticated peer never receives anything derived from the key; only then does the server connect to the agent. Binding to the session defeats man-in-the-middle and replay, so both ends are authenticated and the traffic is encrypted. Client and server must run the same version (no plaintext fallback).

**Limits:** the shared key is the only secret; anyone who has it can impersonate either side, so keep it private and rotate it by hand. On Windows the `ssh-agent` service must be running and the server must run as the same user. Pageant is not supported.

## License

MIT — see [LICENSE](LICENSE).
