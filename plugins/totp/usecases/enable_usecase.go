package usecases

import (
	"context"
	"encoding/json"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/repository"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/services"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/types"
	rootservices "github.com/GoBetterAuth/go-better-auth/v2/services"
)

type enableUseCase struct {
	UserService       rootservices.UserService
	AccountService    rootservices.AccountService
	PasswordService   rootservices.PasswordService
	TokenService      rootservices.TokenService
	TOTPService       *services.TOTPService
	BackupCodeService *services.BackupCodeService
	TOTPRepo          *repository.TOTPRepository
	Config            *types.TOTPPluginConfig
	EventBus          models.EventBus
	Logger            models.Logger
}

func NewEnableUseCase(
	userService rootservices.UserService,
	accountService rootservices.AccountService,
	passwordService rootservices.PasswordService,
	tokenService rootservices.TokenService,
	totpService *services.TOTPService,
	backupCodeService *services.BackupCodeService,
	totpRepo *repository.TOTPRepository,
	config *types.TOTPPluginConfig,
	eventBus models.EventBus,
	logger models.Logger,
) EnableUseCase {
	return &enableUseCase{
		UserService:       userService,
		AccountService:    accountService,
		PasswordService:   passwordService,
		TokenService:      tokenService,
		TOTPService:       totpService,
		BackupCodeService: backupCodeService,
		TOTPRepo:          totpRepo,
		Config:            config,
		EventBus:          eventBus,
		Logger:            logger,
	}
}

func (uc *enableUseCase) Enable(ctx context.Context, userID, password, issuer string) (*types.EnableResult, error) {
	if err := verifyPassword(ctx, uc.AccountService, uc.PasswordService, userID, password); err != nil {
		return nil, err
	}

	existing, err := uc.TOTPRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, constants.ErrTOTPAlreadyEnabled
	}

	user, err := uc.UserService.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, constants.ErrUserNotFound
	}

	secret, err := uc.TOTPService.GenerateSecret()
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := uc.TokenService.Encrypt(secret)
	if err != nil {
		return nil, err
	}

	backupCodes, err := uc.BackupCodeService.Generate()
	if err != nil {
		return nil, err
	}
	hashedCodes, err := uc.BackupCodeService.HashCodes(backupCodes)
	if err != nil {
		return nil, err
	}
	hashedJSON, err := json.Marshal(hashedCodes)
	if err != nil {
		return nil, err
	}

	if err := uc.TOTPRepo.DeleteByUserID(ctx, userID); err != nil {
		return nil, err
	}

	_, err = uc.TOTPRepo.Create(ctx, userID, encryptedSecret, string(hashedJSON))
	if err != nil {
		return nil, err
	}

	if uc.Config.SkipVerificationOnEnable {
		if err := uc.TOTPRepo.SetEnabled(ctx, userID, true); err != nil {
			return nil, err
		}
	}

	if issuer == "" {
		issuer = uc.Config.Issuer
	}
	totpURI := uc.TOTPService.BuildURI(secret, issuer, user.Email)

	publishEvent(uc.EventBus, uc.Logger, constants.EventTOTPEnabled, userID)

	return &types.EnableResult{
		TotpURI:     totpURI,
		BackupCodes: backupCodes,
	}, nil
}
