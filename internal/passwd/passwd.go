// Package passwd implements argon2id password hashing in the PHC string
// format and constant-time verification. It sits behind the service layer
// so hashing parameters are centralized.
package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	timeCost   uint32 = 1
	memoryCost uint32 = 64 * 1024 // 64 MiB
	threads    uint8  = 4
	keyLen     uint32 = 32
	saltLen    int    = 16
)

// Hash derives an argon2id PHC string: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwd: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryCost, timeCost, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks a password against a PHC string in constant time. Malformed
// stored hashes verify as false (never an error) so callers cannot
// distinguish "no hash" from "wrong password" by error type.
func Verify(password, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || !strings.HasPrefix(parts[2], "v=") {
		return false
	}
	var (
		m, t uint32
		p    uint8
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
