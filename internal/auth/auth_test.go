package auth

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndSessionTokens(t *testing.T) {
	secret, err := Token()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := HashPassword(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, secret) || !VerifyPassword(encoded, secret) || VerifyPassword(encoded, secret+"x") {
		t.Fatal("password hash verification failed")
	}
	if !ValidToken(secret) || ValidToken(secret[:10]) || bytes.Contains(TokenHash(secret), []byte(secret)) {
		t.Fatal("invalid session token representation")
	}
	if VerifyPassword("$"+hashAlgorithm+"$v=19$m=999999999,t=3,p=2$bad$bad", secret) {
		t.Fatal("unbounded hash parameters were accepted")
	}
}

func TestLoginLimiterExpiresAndResets(t *testing.T) {
	var limiter Limiter
	now := time.Now()
	for index := 0; index < 10; index++ {
		if !limiter.Allow("test-client", now) {
			t.Fatal("client was limited too early")
		}
	}
	if limiter.Allow("test-client", now) {
		t.Fatal("repeated attempts were not limited")
	}
	limiter.Reset("test-client")
	if !limiter.Allow("test-client", now) || !limiter.Allow("test-client", now.Add(6*time.Minute)) {
		t.Fatal("limiter did not reset or expire")
	}
}
