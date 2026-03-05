package handlers

import (
	"context"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
)

// VerificationService provides access to verification records for the
// two-factor pending authentication flow.
type VerificationService interface {
	FindByToken(ctx context.Context, hashedToken string, verificationType models.VerificationType) (*models.Verification, error)
	Delete(ctx context.Context, id string) error
}

// TokenService provides token hashing for cookie-based lookups.
type TokenService interface {
	Hash(token string) string
}

// UserService provides read access to user records so handlers can
// retrieve supplementary fields (e.g. email) without depending on a
// full user repository.
type UserService interface {
	GetByID(ctx context.Context, id string) (*models.User, error)
}
