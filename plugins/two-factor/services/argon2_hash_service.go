package services

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

// Argon2HashService provides Argon2-based hashing and verification
// for backup codes in the two-factor plugin.
type Argon2HashService struct{}

func NewArgon2HashService() *Argon2HashService {
	return &Argon2HashService{}
}

func (p *Argon2HashService) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	full := append(salt, hash...)
	return base64.RawStdEncoding.EncodeToString(full), nil
}

func (p *Argon2HashService) Verify(password, encoded string) bool {
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(data) < 16 {
		return false
	}
	salt := data[:16]
	hash := data[16:]
	computed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	if len(computed) != len(hash) {
		return false
	}
	for i := range hash {
		if computed[i] != hash[i] {
			return false
		}
	}
	return true
}
