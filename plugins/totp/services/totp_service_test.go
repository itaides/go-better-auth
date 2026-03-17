package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSecret(t *testing.T) {
	svc := NewTOTPService(6, 30)
	secret, err := svc.GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Len(t, secret, 32) // Base32 encoded 20 bytes = 32 chars
}

func TestGenerateAndVerifyCode(t *testing.T) {
	svc := NewTOTPService(6, 30)
	secret, err := svc.GenerateSecret()
	require.NoError(t, err)

	code, err := svc.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	assert.Len(t, code, 6)

	assert.True(t, svc.ValidateCode(secret, code, time.Now()))
}

func TestValidateCodeRejectsWrongCode(t *testing.T) {
	svc := NewTOTPService(6, 30)
	secret, err := svc.GenerateSecret()
	require.NoError(t, err)

	assert.False(t, svc.ValidateCode(secret, "000000", time.Now()))
}

func TestValidateCodeAcceptsAdjacentWindows(t *testing.T) {
	svc := NewTOTPService(6, 30)
	secret, err := svc.GenerateSecret()
	require.NoError(t, err)

	// Generate code for 30 seconds ago (t-1 window)
	past := time.Now().Add(-30 * time.Second)
	code, err := svc.GenerateCode(secret, past)
	require.NoError(t, err)

	// Should still validate at current time (within ±1 window)
	assert.True(t, svc.ValidateCode(secret, code, time.Now()))
}

func TestBuildURI(t *testing.T) {
	svc := NewTOTPService(6, 30)
	uri := svc.BuildURI("JBSWY3DPEHPK3PXP", "MyApp", "user@example.com")
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "secret=JBSWY3DPEHPK3PXP")
	assert.Contains(t, uri, "issuer=MyApp")
	assert.Contains(t, uri, "digits=6")
	assert.Contains(t, uri, "period=30")
}
