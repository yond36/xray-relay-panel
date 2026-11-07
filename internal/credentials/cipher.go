package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MasterKeyEnv = "XRAY_RELAY_PANEL_MASTER_KEY"

// Cipher encrypts entire persisted records. The record's table and ID are
// authenticated as associated data so ciphertext cannot be moved between rows.
type Cipher struct{ aead cipher.AEAD }

func New(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Load creates a persistent, owner-only key unless the environment supplies a
// base64 or hexadecimal encoded 256-bit key. An existing key is never replaced.
func Load(dataDir string) (*Cipher, error) {
	if value, ok := os.LookupEnv(MasterKeyEnv); ok {
		key, err := parseKey(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", MasterKeyEnv, err)
		}
		defer clear(key)
		return New(key)
	}
	path := filepath.Join(dataDir, "master.key")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("master key must be a regular file")
		}
		return loadKeyFile(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect master key: %w", err)
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		// A second process may have won creation but not finished its write.
		for attempt := 0; attempt < 10; attempt++ {
			c, readErr := loadKeyFile(path)
			if readErr == nil {
				return c, nil
			}
			time.Sleep(20 * time.Millisecond)
		}
		return nil, errors.New("cannot read concurrently created master key")
	}
	if err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	_, writeErr := file.Write(key)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("persist master key: %w", writeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close master key: %w", closeErr)
	}
	return New(key)
}

func loadKeyFile(path string) (*Cipher, error) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("master key must be a regular file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, fmt.Errorf("protect master key: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open master key: %w", err)
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, fmt.Errorf("read master key: %w", err)
	}
	defer clear(key)
	return New(key)
}

func parseKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if key, err := hex.DecodeString(value); err == nil && len(key) == 32 {
		return key, nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := encoding.DecodeString(value); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	return nil, errors.New("expected base64 or hex encoded 32-byte key")
}

func (c *Cipher) Seal(plaintext []byte, associatedData string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	value := append([]byte{1}, nonce...)
	return c.aead.Seal(value, nonce, plaintext, []byte(associatedData)), nil
}

func (c *Cipher) Open(value []byte, associatedData string) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(value) < 1+nonceSize+c.aead.Overhead() || value[0] != 1 {
		return nil, errors.New("invalid encrypted record")
	}
	plaintext, err := c.aead.Open(nil, value[1:1+nonceSize], value[1+nonceSize:], []byte(associatedData))
	if err != nil {
		return nil, errors.New("cannot decrypt record; check the persisted master key")
	}
	return plaintext, nil
}
