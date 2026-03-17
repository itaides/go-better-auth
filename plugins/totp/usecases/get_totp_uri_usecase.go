package usecases

import (
	"context"

	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/repository"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/services"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/types"
	rootservices "github.com/GoBetterAuth/go-better-auth/v2/services"
)

type getTOTPURIUseCase struct {
	UserService     rootservices.UserService
	AccountService  rootservices.AccountService
	PasswordService rootservices.PasswordService
	TokenService    rootservices.TokenService
	TOTPService     *services.TOTPService
	TOTPRepo        *repository.TOTPRepository
	Config          *types.TOTPPluginConfig
}

func NewGetTOTPURIUseCase(
	userService rootservices.UserService,
	accountService rootservices.AccountService,
	passwordService rootservices.PasswordService,
	tokenService rootservices.TokenService,
	totpService *services.TOTPService,
	totpRepo *repository.TOTPRepository,
	config *types.TOTPPluginConfig,
) GetTOTPURIUseCase {
	return &getTOTPURIUseCase{
		UserService:     userService,
		AccountService:  accountService,
		PasswordService: passwordService,
		TokenService:    tokenService,
		TOTPService:     totpService,
		TOTPRepo:        totpRepo,
		Config:          config,
	}
}

func (uc *getTOTPURIUseCase) GetTOTPURI(ctx context.Context, userID, password string) (string, error) {
	if err := verifyPassword(ctx, uc.AccountService, uc.PasswordService, userID, password); err != nil {
		return "", err
	}

	record, err := uc.TOTPRepo.GetByUserID(ctx, userID)
	if err != nil {
		return "", err
	}
	if record == nil {
		return "", constants.ErrTOTPNotEnabled
	}

	user, err := uc.UserService.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	if user == nil {
		return "", constants.ErrUserNotFound
	}

	secret, err := uc.TokenService.Decrypt(record.Secret)
	if err != nil {
		return "", err
	}

	issuer := uc.Config.Issuer
	return uc.TOTPService.BuildURI(secret, issuer, user.Email), nil
}
