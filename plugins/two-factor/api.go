package twofactor

import (
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/two-factor/usecases"
)

type API struct {
	useCases *usecases.UseCases
}

func BuildAPI(plugin *TwoFactorPlugin) *API {
	useCases := BuildUseCases(plugin)
	return &API{useCases: useCases}
}

func BuildUseCases(p *TwoFactorPlugin) *usecases.UseCases {
	return &usecases.UseCases{
		Enable: usecases.NewEnableUseCase(
			p.accountService,
			p.passwordService,
			p.tokenService,
			p.totpService,
			p.backupCodeService,
			p.repo,
			p.pluginConfig,
		),
		Disable: usecases.NewDisableUseCase(
			p.accountService,
			p.passwordService,
			p.repo,
		),
		GetTOTPURI: usecases.NewGetTOTPURIUseCase(
			p.accountService,
			p.passwordService,
			p.tokenService,
			p.totpService,
			p.repo,
			p.pluginConfig,
		),
		VerifyTOTP: usecases.NewVerifyTOTPUseCase(
			p.tokenService,
			p.sessionService,
			p.userService,
			p.totpService,
			p.repo,
			p.globalConfig,
			p.pluginConfig,
		),
		GenerateBackupCodes: usecases.NewGenerateBackupCodesUseCase(
			p.accountService,
			p.passwordService,
			p.tokenService,
			p.backupCodeService,
			p.repo,
		),
		VerifyBackupCode: usecases.NewVerifyBackupCodeUseCase(
			p.tokenService,
			p.sessionService,
			p.userService,
			p.backupCodeService,
			p.repo,
			p.globalConfig,
			p.pluginConfig,
		),
		ViewBackupCodes: usecases.NewViewBackupCodesUseCase(
			p.tokenService,
			p.repo,
		),
	}
}
