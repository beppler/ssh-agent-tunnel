package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMAC(t *testing.T) {
	k := []byte("0123456789abcdef0123456789abcdef")
	c, _ := newChallenge()
	m := computeMAC(k, c)
	if !verifyMAC(k, c, m) {
		t.Fatal("valid mac rejected")
	}
	if string(computeMAC(k, c)) != string(m) {
		t.Fatal("not deterministic")
	}
	if verifyMAC([]byte("different-key-different-key-diffe"), c, m) {
		t.Fatal("wrong key accepted")
	}
	c2, _ := newChallenge()
	if verifyMAC(k, c2, m) {
		t.Fatal("wrong challenge accepted")
	}
	m[0] ^= 1
	if verifyMAC(k, c, m) {
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
