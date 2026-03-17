package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/types"
)

// ---------------------------------------------------------------------------
// Mock use cases
// ---------------------------------------------------------------------------

type mockEnableUC struct {
	fn func(ctx context.Context, userID, password, issuer string) (*types.EnableResult, error)
}

func (m *mockEnableUC) Enable(ctx context.Context, userID, password, issuer string) (*types.EnableResult, error) {
	return m.fn(ctx, userID, password, issuer)
}

type mockDisableUC struct {
	fn func(ctx context.Context, userID, password string) error
}

func (m *mockDisableUC) Disable(ctx context.Context, userID, password string) error {
	return m.fn(ctx, userID, password)
}

type mockGetTOTPURIUC struct {
	fn func(ctx context.Context, userID, password string) (string, error)
}

func (m *mockGetTOTPURIUC) GetTOTPURI(ctx context.Context, userID, password string) (string, error) {
	return m.fn(ctx, userID, password)
}

type mockGenerateBackupCodesUC struct {
	fn func(ctx context.Context, userID, password string) ([]string, error)
}

func (m *mockGenerateBackupCodesUC) Generate(ctx context.Context, userID, password string) ([]string, error) {
	return m.fn(ctx, userID, password)
}

type mockViewBackupCodesUC struct {
	fn func(ctx context.Context, userID, password string) (int, error)
}

func (m *mockViewBackupCodesUC) View(ctx context.Context, userID, password string) (int, error) {
	return m.fn(ctx, userID, password)
}

type mockVerifyTOTPUC struct {
	fn func(ctx context.Context, pendingToken, code string, trustDevice bool, ipAddress, userAgent *string) (*types.VerifyResult, error)
}

func (m *mockVerifyTOTPUC) Verify(ctx context.Context, pendingToken, code string, trustDevice bool, ipAddress, userAgent *string) (*types.VerifyResult, error) {
	return m.fn(ctx, pendingToken, code, trustDevice, ipAddress, userAgent)
}

type mockVerifyBackupCodeUC struct {
	fn func(ctx context.Context, pendingToken, code string, trustDevice bool, ipAddress, userAgent *string) (*types.VerifyResult, error)
}

func (m *mockVerifyBackupCodeUC) Verify(ctx context.Context, pendingToken, code string, trustDevice bool, ipAddress, userAgent *string) (*types.VerifyResult, error) {
	return m.fn(ctx, pendingToken, code, trustDevice, ipAddress, userAgent)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newAuthenticatedRequest(t *testing.T, method, path string, body any) (*http.Request, *models.RequestContext, *httptest.ResponseRecorder) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	userID := "user-1"
	reqCtx := &models.RequestContext{
		Request:        req,
		ResponseWriter: w,
		Values:         make(map[string]any),
		UserID:         &userID,
	}
	ctx := models.SetRequestContext(context.Background(), reqCtx)
	req = req.WithContext(ctx)
	reqCtx.Request = req
	return req, reqCtx, w
}

func newUnauthenticatedRequest(t *testing.T, method, path string, body any) (*http.Request, *models.RequestContext, *httptest.ResponseRecorder) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	reqCtx := &models.RequestContext{
		Request:        req,
		ResponseWriter: w,
		Values:         make(map[string]any),
	}
	ctx := models.SetRequestContext(context.Background(), reqCtx)
	req = req.WithContext(ctx)
	reqCtx.Request = req
	return req, reqCtx, w
}

func newPendingCookieRequest(t *testing.T, path string, body any, pendingToken string) (*http.Request, *models.RequestContext, *httptest.ResponseRecorder) {
	t.Helper()
	req, reqCtx, w := newAuthenticatedRequest(t, "POST", path, body)
	req.AddCookie(&http.Cookie{Name: constants.CookieTOTPPending, Value: pendingToken})
	return req, reqCtx, w
}

func parseJSONResponse(t *testing.T, body []byte, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(body, v))
}

// ---------------------------------------------------------------------------
// EnableHandler tests
// ---------------------------------------------------------------------------

func TestEnableHandler_Success(t *testing.T) {
	uc := &mockEnableUC{fn: func(_ context.Context, _, _, _ string) (*types.EnableResult, error) {
		return &types.EnableResult{
			TotpURI:     "otpauth://totp/App:user@test.com?secret=ABC",
			BackupCodes: []string{"code1", "code2"},
		}, nil
	}}
	h := &EnableHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/enable", types.EnableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	var resp types.EnableResponse
	parseJSONResponse(t, reqCtx.ResponseBody, &resp)
	assert.NotEmpty(t, resp.TotpURI)
	assert.Len(t, resp.BackupCodes, 2)
}

func TestEnableHandler_Unauthenticated(t *testing.T) {
	h := &EnableHandler{UseCase: &mockEnableUC{}}
	req, reqCtx, w := newUnauthenticatedRequest(t, "POST", "/totp/enable", types.EnableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	assert.True(t, reqCtx.Handled)
}

func TestEnableHandler_InvalidBody(t *testing.T) {
	h := &EnableHandler{UseCase: &mockEnableUC{}}
	req := httptest.NewRequest("POST", "/totp/enable", bytes.NewReader([]byte("not-json")))
	w := httptest.NewRecorder()
	userID := "user-1"
	reqCtx := &models.RequestContext{
		Request:        req,
		ResponseWriter: w,
		Values:         make(map[string]any),
		UserID:         &userID,
	}
	ctx := models.SetRequestContext(context.Background(), reqCtx)
	req = req.WithContext(ctx)
	reqCtx.Request = req

	h.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, reqCtx.ResponseStatus)
}

func TestEnableHandler_UseCaseError(t *testing.T) {
	uc := &mockEnableUC{fn: func(_ context.Context, _, _, _ string) (*types.EnableResult, error) {
		return nil, constants.ErrTOTPAlreadyEnabled
	}}
	h := &EnableHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/enable", types.EnableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// DisableHandler tests
// ---------------------------------------------------------------------------

func TestDisableHandler_Success(t *testing.T) {
	uc := &mockDisableUC{fn: func(_ context.Context, _, _ string) error { return nil }}
	h := &DisableHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/disable", types.DisableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
}

func TestDisableHandler_Unauthenticated(t *testing.T) {
	h := &DisableHandler{UseCase: &mockDisableUC{}}
	req, reqCtx, w := newUnauthenticatedRequest(t, "POST", "/totp/disable", types.DisableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

func TestDisableHandler_UseCaseError(t *testing.T) {
	uc := &mockDisableUC{fn: func(_ context.Context, _, _ string) error {
		return constants.ErrTOTPNotEnabled
	}}
	h := &DisableHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/disable", types.DisableRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// GetTOTPURIHandler tests
// ---------------------------------------------------------------------------

func TestGetTOTPURIHandler_Success(t *testing.T) {
	uc := &mockGetTOTPURIUC{fn: func(_ context.Context, _, _ string) (string, error) {
		return "otpauth://totp/App:user@test.com?secret=ABC", nil
	}}
	h := &GetTOTPURIHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/get-uri", types.GetTOTPURIRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	var resp types.GetTOTPURIResponse
	parseJSONResponse(t, reqCtx.ResponseBody, &resp)
	assert.NotEmpty(t, resp.TotpURI)
}

func TestGetTOTPURIHandler_Unauthenticated(t *testing.T) {
	h := &GetTOTPURIHandler{UseCase: &mockGetTOTPURIUC{}}
	req, reqCtx, w := newUnauthenticatedRequest(t, "POST", "/totp/get-uri", types.GetTOTPURIRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

func TestGetTOTPURIHandler_UseCaseError(t *testing.T) {
	uc := &mockGetTOTPURIUC{fn: func(_ context.Context, _, _ string) (string, error) {
		return "", constants.ErrTOTPNotEnabled
	}}
	h := &GetTOTPURIHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/get-uri", types.GetTOTPURIRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// GenerateBackupCodesHandler tests
// ---------------------------------------------------------------------------

func TestGenerateBackupCodesHandler_Success(t *testing.T) {
	uc := &mockGenerateBackupCodesUC{fn: func(_ context.Context, _, _ string) ([]string, error) {
		return []string{"a1", "b2", "c3"}, nil
	}}
	h := &GenerateBackupCodesHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/generate-backup-codes", types.GenerateBackupCodesRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	var resp types.GenerateBackupCodesResponse
	parseJSONResponse(t, reqCtx.ResponseBody, &resp)
	assert.Len(t, resp.BackupCodes, 3)
}

func TestGenerateBackupCodesHandler_Unauthenticated(t *testing.T) {
	h := &GenerateBackupCodesHandler{UseCase: &mockGenerateBackupCodesUC{}}
	req, reqCtx, w := newUnauthenticatedRequest(t, "POST", "/totp/generate-backup-codes", types.GenerateBackupCodesRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// ViewBackupCodesHandler tests
// ---------------------------------------------------------------------------

func TestViewBackupCodesHandler_Success(t *testing.T) {
	uc := &mockViewBackupCodesUC{fn: func(_ context.Context, _, _ string) (int, error) {
		return 7, nil
	}}
	h := &ViewBackupCodesHandler{UseCase: uc}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/view-backup-codes", types.ViewBackupCodesRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	var resp types.ViewBackupCodesResponse
	parseJSONResponse(t, reqCtx.ResponseBody, &resp)
	assert.Equal(t, 7, resp.RemainingCount)
}

func TestViewBackupCodesHandler_Unauthenticated(t *testing.T) {
	h := &ViewBackupCodesHandler{UseCase: &mockViewBackupCodesUC{}}
	req, reqCtx, w := newUnauthenticatedRequest(t, "POST", "/totp/view-backup-codes", types.ViewBackupCodesRequest{Password: "pass"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// VerifyTOTPHandler tests
// ---------------------------------------------------------------------------

func newVerifyResult() *types.VerifyResult {
	return &types.VerifyResult{
		User:         &models.User{ID: "user-1", Email: "test@example.com"},
		Session:      &models.Session{ID: "session-1", UserID: "user-1", ExpiresAt: time.Now().Add(24 * time.Hour)},
		SessionToken: "session-token-xyz",
	}
}

func TestVerifyTOTPHandler_Success(t *testing.T) {
	uc := &mockVerifyTOTPUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return newVerifyResult(), nil
	}}
	cfg := &types.TOTPPluginConfig{SameSite: "lax"}
	h := &VerifyTOTPHandler{UseCase: uc, PluginConfig: cfg}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify", types.VerifyTOTPRequest{Code: "123456"}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	assert.Equal(t, true, reqCtx.Values[models.ContextAuthSuccess.String()])
	assert.Equal(t, "session-1", reqCtx.Values[models.ContextSessionID.String()])
	assert.Equal(t, "session-token-xyz", reqCtx.Values[models.ContextSessionToken.String()])

	// Verify pending cookie is cleared
	cookies := w.Result().Cookies()
	var pendingCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == constants.CookieTOTPPending {
			pendingCookie = c
		}
	}
	require.NotNil(t, pendingCookie)
	assert.Equal(t, -1, pendingCookie.MaxAge)
	assert.Empty(t, pendingCookie.Value)
}

func TestVerifyTOTPHandler_WithTrustedDevice(t *testing.T) {
	result := newVerifyResult()
	result.TrustedDeviceToken = "trusted-device-token-123"

	uc := &mockVerifyTOTPUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return result, nil
	}}
	cfg := &types.TOTPPluginConfig{
		TrustedDeviceDuration: 30 * 24 * time.Hour,
		SecureCookie:          true,
		SameSite:              "strict",
	}
	h := &VerifyTOTPHandler{UseCase: uc, PluginConfig: cfg}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify", types.VerifyTOTPRequest{Code: "123456", TrustDevice: true}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)

	cookies := w.Result().Cookies()
	var trustedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == constants.CookieTOTPTrusted {
			trustedCookie = c
		}
	}
	require.NotNil(t, trustedCookie, "expected trusted device cookie to be set")
	assert.Equal(t, "trusted-device-token-123", trustedCookie.Value)
	assert.Equal(t, int(cfg.TrustedDeviceDuration.Seconds()), trustedCookie.MaxAge)
	assert.True(t, trustedCookie.Secure)
	assert.True(t, trustedCookie.HttpOnly)
}

func TestVerifyTOTPHandler_MissingPendingCookie(t *testing.T) {
	h := &VerifyTOTPHandler{UseCase: &mockVerifyTOTPUC{}, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/verify", types.VerifyTOTPRequest{Code: "123456"})
	// No pending cookie added
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	assert.True(t, reqCtx.Handled)
}

func TestVerifyTOTPHandler_InvalidBody(t *testing.T) {
	h := &VerifyTOTPHandler{UseCase: &mockVerifyTOTPUC{}, PluginConfig: &types.TOTPPluginConfig{}}

	req := httptest.NewRequest("POST", "/totp/verify", bytes.NewReader([]byte("bad")))
	req.AddCookie(&http.Cookie{Name: constants.CookieTOTPPending, Value: "token"})
	w := httptest.NewRecorder()
	reqCtx := &models.RequestContext{
		Request:        req,
		ResponseWriter: w,
		Values:         make(map[string]any),
	}
	ctx := models.SetRequestContext(context.Background(), reqCtx)
	req = req.WithContext(ctx)
	reqCtx.Request = req

	h.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnprocessableEntity, reqCtx.ResponseStatus)
}

func TestVerifyTOTPHandler_InvalidCode(t *testing.T) {
	uc := &mockVerifyTOTPUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return nil, constants.ErrInvalidTOTPCode
	}}
	h := &VerifyTOTPHandler{UseCase: uc, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify", types.VerifyTOTPRequest{Code: "000000"}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

func TestVerifyTOTPHandler_TOTPNotEnabled(t *testing.T) {
	uc := &mockVerifyTOTPUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return nil, constants.ErrTOTPNotEnabled
	}}
	h := &VerifyTOTPHandler{UseCase: uc, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify", types.VerifyTOTPRequest{Code: "123456"}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

// ---------------------------------------------------------------------------
// VerifyBackupCodeHandler tests
// ---------------------------------------------------------------------------

func TestVerifyBackupCodeHandler_Success(t *testing.T) {
	uc := &mockVerifyBackupCodeUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return newVerifyResult(), nil
	}}
	cfg := &types.TOTPPluginConfig{SameSite: "lax"}
	h := &VerifyBackupCodeHandler{UseCase: uc, PluginConfig: cfg}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify-backup-code", types.VerifyBackupCodeRequest{Code: "abc123"}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)
	assert.Equal(t, true, reqCtx.Values[models.ContextAuthSuccess.String()])
	assert.Equal(t, "session-1", reqCtx.Values[models.ContextSessionID.String()])
}

func TestVerifyBackupCodeHandler_WithTrustedDevice(t *testing.T) {
	result := newVerifyResult()
	result.TrustedDeviceToken = "trusted-token"

	uc := &mockVerifyBackupCodeUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return result, nil
	}}
	cfg := &types.TOTPPluginConfig{
		TrustedDeviceDuration: 7 * 24 * time.Hour,
		SecureCookie:          true,
		SameSite:              "none",
	}
	h := &VerifyBackupCodeHandler{UseCase: uc, PluginConfig: cfg}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify-backup-code", types.VerifyBackupCodeRequest{Code: "abc123", TrustDevice: true}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, reqCtx.ResponseStatus)

	cookies := w.Result().Cookies()
	var trustedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == constants.CookieTOTPTrusted {
			trustedCookie = c
		}
	}
	require.NotNil(t, trustedCookie)
	assert.Equal(t, "trusted-token", trustedCookie.Value)
	assert.True(t, trustedCookie.Secure)
}

func TestVerifyBackupCodeHandler_MissingPendingCookie(t *testing.T) {
	h := &VerifyBackupCodeHandler{UseCase: &mockVerifyBackupCodeUC{}, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newAuthenticatedRequest(t, "POST", "/totp/verify-backup-code", types.VerifyBackupCodeRequest{Code: "abc123"})
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

func TestVerifyBackupCodeHandler_InvalidCode(t *testing.T) {
	uc := &mockVerifyBackupCodeUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return nil, constants.ErrInvalidBackupCode
	}}
	h := &VerifyBackupCodeHandler{UseCase: uc, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify-backup-code", types.VerifyBackupCodeRequest{Code: "wrong"}, "pending-abc")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}

func TestVerifyBackupCodeHandler_InvalidPendingToken(t *testing.T) {
	uc := &mockVerifyBackupCodeUC{fn: func(_ context.Context, _, _ string, _ bool, _, _ *string) (*types.VerifyResult, error) {
		return nil, constants.ErrInvalidPendingToken
	}}
	h := &VerifyBackupCodeHandler{UseCase: uc, PluginConfig: &types.TOTPPluginConfig{}}

	req, reqCtx, w := newPendingCookieRequest(t, "/totp/verify-backup-code", types.VerifyBackupCodeRequest{Code: "abc123"}, "bad-token")
	h.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
}
