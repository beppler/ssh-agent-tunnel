package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	challengeSize = 32
	minKeySize    = 32
	keyEnv        = "SSH_AGENT_TUNNEL_KEY"
	macContext    = "ssh-agent-tunnel/v1"
)

func newChallenge() ([]byte, error) {
	c := make([]byte, challengeSize)
	_, err := rand.Read(c)
	return c, err
}

func computeMAC(key, challenge []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(macContext))
	h.Write(challenge)
	return h.Sum(nil)
}

func verifyMAC(key, challenge, got []byte) bool {
	return hmac.Equal(computeMAC(key, challenge), got)
}

// loadKey reads the shared key from path, or from $SSH_AGENT_TUNNEL_KEY if path is empty.
func loadKey(path string) ([]byte, error) {
	var key string
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		key = string(b)
	} else {
		key = os.Getenv(keyEnv)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("no key: use -key-file or %s", keyEnv)
	}
	if len(key) < minKeySize {
		return nil, errors.New("key must be at least 32 bytes")
	}
	return []byte(key), nil
}
