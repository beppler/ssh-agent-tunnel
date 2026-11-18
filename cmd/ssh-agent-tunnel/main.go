package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.beppler.dev.br/ssh-agent-tunnel"
)

const usage = "usage: ssh-agent-tunnel server|client|version [flags]"

func main() {
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		keyFile := fs.String("key-file", "", "shared key file (default: $"+tunnel.KeyEnv+")")
		listen := fs.String("listen", "127.0.0.1:7722", "TCP listen address")
		agent := fs.String("agent", tunnel.DefaultAgentPath(), "agent unix socket or Windows named pipe")
		fs.Parse(os.Args[2:])
		key := mustKey(*keyFile)
		if *agent == "" {
			log.Fatal("no agent path: use -agent or set SSH_AUTH_SOCK")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("listening on %s, agent %s", ln.Addr(), *agent)
		srv := &tunnel.Server{Key: key, AgentPath: *agent, Logger: slog.Default()}
		if err := srv.Serve(ctx, ln); err != nil {
			log.Fatal(err)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		keyFile := fs.String("key-file", "", "shared key file (default: $"+tunnel.KeyEnv+")")
		server := fs.String("server", "host.docker.internal:7722", "server address")
		sock := fs.String("socket", "/run/ssh-agent.sock", "unix socket to create")
		fs.Parse(os.Args[2:])
		key := mustKey(*keyFile)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ln, err := tunnel.ListenUnix(*sock)
		if err != nil {
			log.Fatal(err)
		}
		defer os.Remove(*sock)
		log.Printf("socket %s -> %s", *sock, *server)
		cli := &tunnel.Client{Key: key, ServerAddr: *server, Logger: slog.Default()}
		if err := cli.Serve(ctx, ln); err != nil {
			log.Fatal(err)
		}
	case "version":
		fmt.Println(tunnel.ProtocolVersion)
	default:
		log.Fatal(usage)
	}
}

func mustKey(path string) []byte {
	k, err := tunnel.LoadKey(path)
	if err != nil {
		log.Fatal(err)
	}
	return k
}
