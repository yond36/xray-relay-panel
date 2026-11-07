package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"xrayrelay/internal/model"
)

const SessionDuration = 12 * time.Hour

type principalKey struct{}

func WithPrincipal(ctx context.Context, user model.User) context.Context {
	return context.WithValue(ctx, principalKey{}, user)
}

func Principal(ctx context.Context) (model.User, bool) {
	user, ok := ctx.Value(principalKey{}).(model.User)
	return user, ok && user.ID != "" && (user.Role == model.RoleAdmin || user.Role == model.RoleUser)
}

func CanonicalUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !utf8.ValidString(username) || username == "" || utf8.RuneCountInString(username) > 64 {
		return "", errors.New("用户名须为 1–64 个有效字符")
	}
	for _, char := range username {
		if unicode.IsControl(char) {
			return "", errors.New("用户名不能包含控制字符")
		}
	}
	return username, nil
}

const hashAlgorithm = "argon2" + "id"

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("密码长度须为 12–1024 字节")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	defer clear(key)
	return fmt.Sprintf("$%s$v=19$m=65536,t=3,p=2$%s$%s", hashAlgorithm, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, password string) bool {
	if len(password) > 1024 {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != hashAlgorithm || parts[2] != "v=19" {
		return false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false
	}
	parse := func(value, prefix string) (uint64, error) {
		if !strings.HasPrefix(value, prefix) {
			return 0, errors.New("invalid argon2 parameters")
		}
		return strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	}
	memory, errM := parse(params[0], "m=")
	iterations, errT := parse(params[1], "t=")
	parallelism, errP := parse(params[2], "p=")
	// Bound persisted parameters before allocating any memory.
	if errM != nil || errT != nil || errP != nil || memory < 8*1024 || memory > 128*1024 || iterations < 1 || iterations > 6 || parallelism < 1 || parallelism > 8 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(expected)))
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func Token() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func TokenHash(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

func ValidToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32
}

// Limiter bounds password work by source address without retaining unbounded
// attacker-controlled keys. Successful authentication clears that address.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]attempts
}

type attempts struct {
	start time.Time
	count int
}

func (l *Limiter) Allow(address string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]attempts)
	}
	for key, item := range l.entries {
		if now.Sub(item.start) >= 5*time.Minute {
			delete(l.entries, key)
		}
	}
	item, ok := l.entries[address]
	if !ok {
		if len(l.entries) >= 2048 {
			return false
		}
		item.start = now
	}
	if item.count >= 10 {
		return false
	}
	item.count++
	l.entries[address] = item
	return true
}

func (l *Limiter) Reset(address string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, address)
}
