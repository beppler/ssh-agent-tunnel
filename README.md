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

Protocol: server sends 32 random bytes; client replies `HMAC-SHA256(key, "ssh-agent-tunnel/v1" || challenge)`; the server checks it in constant time (5s timeout) and only then connects to the agent.

**Limits:** for trusted local links only. Traffic after the handshake is plaintext, and the client does not authenticate the server. On Windows the `ssh-agent` service must be running and the server must run as the same user. Pageant is not supported.
