// Package secret creates and hashes tokens and owner passwords.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Token returns prefix + 256 random bits, base64url encoded.
func Token(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails per crypto/rand docs
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Hash returns the hex SHA-256 of a high-entropy token. Tokens are random, so
// a fast unsalted hash is enough to make a database leak useless.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// UserCode returns an 8-letter pairing code like "BCDF-GHJK" from a
// consonant-only alphabet (RFC 8628 §6.1).
func UserCode() string {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		// 256 % 20 != 0 gives a slight bias; irrelevant for a short-lived,
		// login-gated code.
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}

// NormalizeUserCode uppercases and re-hyphenates user input.
func NormalizeUserCode(s string) string {
	var letters []rune
	for _, r := range strings.ToUpper(s) {
		if r >= 'A' && r <= 'Z' {
			letters = append(letters, r)
		}
	}
	if len(letters) != 8 {
		return ""
	}
	return string(letters[:4]) + "-" + string(letters[4:])
}

// argon2id parameters (OWASP: m=19 MiB, t=2, p=1 minimum; we use more memory).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks pw against an encoded argon2id hash.
func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	var mem, iter uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &threads); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, iter, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
