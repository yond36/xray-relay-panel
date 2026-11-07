package credentials

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRecordAuthenticationAndKeyPersistence(t *testing.T) {
	t.Setenv(MasterKeyEnv, "")
	if err := os.Unsetenv(MasterKeyEnv); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	first, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	sealed, err := first.Seal(secret, "nodes:one")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("ciphertext contains plaintext")
	}
	second, err := Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := second.Open(sealed, "nodes:one")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatal("persisted key did not decrypt the record")
	}
	if _, err := second.Open(sealed, "nodes:two"); err == nil {
		t.Fatal("record could be moved to a different ID")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := second.Open(sealed, "nodes:one"); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	info, err := os.Stat(filepath.Join(directory, "master.key"))
	if err != nil || info.Size() != 32 {
		t.Fatal("master key was not persisted")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("master key permissions are not owner-only")
	}
}

func TestEnvironmentKeyAndInvalidOverride(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv(MasterKeyEnv, base64.StdEncoding.EncodeToString(key))
	directory := t.TempDir()
	if _, err := Load(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "master.key")); !os.IsNotExist(err) {
		t.Fatal("environment override unexpectedly wrote a key file")
	}
	t.Setenv(MasterKeyEnv, "invalid")
	if _, err := Load(directory); err == nil {
		t.Fatal("invalid environment key did not fail closed")
	}
}
