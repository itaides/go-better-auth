package twofactor

import (
	"net/http"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/two-factor/handlers"
)

func Routes(p *TwoFactorPlugin) []models.Route {
	uc := p.Api.useCases

	enableHandler := &handlers.EnableHandler{
		UseCase: uc.Enable,
	}
	disableHandler := &handlers.DisableHandler{
		UseCase: uc.Disable,
	}
	getTOTPURIHandler := &handlers.GetTOTPURIHandler{
		UseCase: uc.GetTOTPURI,
	}
	verifyTOTPHandler := &handlers.VerifyTOTPHandler{
		UseCase:      uc.VerifyTOTP,
		PluginConfig: p.pluginConfig,
	}
	generateBackupCodesHandler := &handlers.GenerateBackupCodesHandler{
		UseCase: uc.GenerateBackupCodes,
	}
	verifyBackupCodeHandler := &handlers.VerifyBackupCodeHandler{
		UseCase:      uc.VerifyBackupCode,
		PluginConfig: p.pluginConfig,
	}
	viewBackupCodesHandler := &handlers.ViewBackupCodesHandler{
		UseCase: uc.ViewBackupCodes,
	}

	return []models.Route{
		{Path: "/two-factor/enable", Method: http.MethodPost, Handler: enableHandler.Handler()},
		{Path: "/two-factor/disable", Method: http.MethodPost, Handler: disableHandler.Handler()},
		{Path: "/two-factor/get-totp-uri", Method: http.MethodPost, Handler: getTOTPURIHandler.Handler()},
		{Path: "/two-factor/verify-totp", Method: http.MethodPost, Handler: verifyTOTPHandler.Handler()},
		{Path: "/two-factor/generate-backup-codes", Method: http.MethodPost, Handler: generateBackupCodesHandler.Handler()},
		{Path: "/two-factor/verify-backup-code", Method: http.MethodPost, Handler: verifyBackupCodeHandler.Handler()},
		{Path: "/two-factor/view-backup-codes", Method: http.MethodPost, Handler: viewBackupCodesHandler.Handler()},
	}
}
