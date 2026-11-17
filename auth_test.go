package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMAC(t *testing.T) {
	k := []byte("0123456789abcdef0123456789abcdef")
	e := []byte("session-one")
	m := computeMAC(k, "server", e)
	if !verifyMAC(k, "server", e, m) {
		t.Fatal("valid mac rejected")
	}
	if verifyMAC([]byte("different-key-different-key-diffe"), "server", e, m) {
		t.Fatal("wrong key accepted")
	}
	if verifyMAC(k, "server", []byte("session-two"), m) {
		t.Fatal("other session accepted")
	}
	if verifyMAC(k, "client", e, m) {
		t.Fatal("reflected role accepted")
	}
	m[0] ^= 1
	if verifyMAC(k, "server", e, m) {
		t.Fatal("tampered mac accepted")
	}
}

func TestLoadKeyShort(t *testing.T) {
	t.Setenv(keyEnv, "short")
	if _, err := loadKey(""); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestLoadKeyFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k")
	os.WriteFile(f, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	k, err := loadKey(f)
	if err != nil || len(k) != 32 {
		t.Fatalf("got %q, %v", k, err)
	}
}
