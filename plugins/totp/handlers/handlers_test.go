package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/types"
)

func newReqCtx(t *testing.T, method, path string, body []byte, userID *string) (*http.Request, *models.RequestContext, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	reqCtx := &models.RequestContext{
		Request:        req,
		ResponseWriter: w,
		Values:         make(map[string]any),
		UserID:         userID,
	}
	ctx := models.SetRequestContext(context.Background(), reqCtx)
	req = req.WithContext(ctx)
	reqCtx.Request = req
	return req, reqCtx, w
}

func TestEnableHandler(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()

		h := &EnableHandler{}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/enable", nil, nil)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	})

	t.Run("invalid_body", func(t *testing.T) {
		t.Parallel()

		uid := "u1"
		h := &EnableHandler{}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/enable", []byte("not-json"), &uid)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, reqCtx.ResponseStatus)
	})
}

func TestDisableHandler(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()

		h := &DisableHandler{}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/disable", nil, nil)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	})
}

func TestGetTOTPURIHandler(t *testing.T) {
	t.Parallel()

	t.Run("unauthenticated", func(t *testing.T) {
		t.Parallel()

		h := &GetTOTPURIHandler{}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/get-uri", nil, nil)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	})
}

func TestVerifyTOTPHandler(t *testing.T) {
	t.Parallel()

	t.Run("missing_pending_cookie", func(t *testing.T) {
		t.Parallel()

		uid := "u1"
		h := &VerifyTOTPHandler{PluginConfig: &types.TOTPPluginConfig{}}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/verify", []byte(`{"code":"123456"}`), &uid)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	})

	t.Run("invalid_body", func(t *testing.T) {
		t.Parallel()

		uid := "u1"
		h := &VerifyTOTPHandler{PluginConfig: &types.TOTPPluginConfig{}}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/verify", []byte("bad"), &uid)
		req.AddCookie(&http.Cookie{Name: "totp_pending", Value: "token"})
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, reqCtx.ResponseStatus)
	})
}

func TestVerifyBackupCodeHandler(t *testing.T) {
	t.Parallel()

	t.Run("missing_pending_cookie", func(t *testing.T) {
		t.Parallel()

		uid := "u1"
		h := &VerifyBackupCodeHandler{PluginConfig: &types.TOTPPluginConfig{}}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/verify-backup-code", []byte(`{"code":"abc"}`), &uid)
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, reqCtx.ResponseStatus)
	})

	t.Run("invalid_body", func(t *testing.T) {
		t.Parallel()

		uid := "u1"
		h := &VerifyBackupCodeHandler{PluginConfig: &types.TOTPPluginConfig{}}
		req, reqCtx, w := newReqCtx(t, http.MethodPost, "/totp/verify-backup-code", []byte("bad"), &uid)
		req.AddCookie(&http.Cookie{Name: "totp_pending", Value: "token"})
		h.Handler().ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnprocessableEntity, reqCtx.ResponseStatus)
	})
}
