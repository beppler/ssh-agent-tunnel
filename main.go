package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: ssh-agent-tunnel server|client [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyFile := fs.String("key-file", "", "shared key file (default: $"+keyEnv+")")
	switch os.Args[1] {
	case "server":
		listen := fs.String("listen", "127.0.0.1:7722", "TCP listen address")
		agent := fs.String("agent", defaultAgentPath(), "agent unix socket or Windows named pipe")
		fs.Parse(os.Args[2:])
		key := mustKey(*keyFile)
		if *agent == "" {
			log.Fatal("no agent path: use -agent or set SSH_AUTH_SOCK")
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("listening on %s, agent %s", ln.Addr(), *agent)
		serve(ln, key, *agent)
	case "client":
		server := fs.String("server", "host.docker.internal:7722", "server address")
		sock := fs.String("socket", "/run/ssh-agent.sock", "unix socket to create")
		fs.Parse(os.Args[2:])
		key := mustKey(*keyFile)
		ln, err := listenUnix(*sock)
		if err != nil {
			log.Fatal(err)
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; ln.Close(); os.Remove(*sock); os.Exit(0) }()
		log.Printf("socket %s -> %s", *sock, *server)
		runClient(ln, key, *server)
	default:
		log.Fatal("usage: ssh-agent-tunnel server|client [flags]")
	}
}

func mustKey(path string) []byte {
	k, err := loadKey(path)
	if err != nil {
		log.Fatal(err)
	}
	return k
}
