package usecases

import (
	"context"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/repository"
	rootservices "github.com/GoBetterAuth/go-better-auth/v2/services"
)

type disableUseCase struct {
	AccountService  rootservices.AccountService
	PasswordService rootservices.PasswordService
	TOTPRepo        *repository.TOTPRepository
	EventBus        models.EventBus
	Logger          models.Logger
}

func NewDisableUseCase(
	accountService rootservices.AccountService,
	passwordService rootservices.PasswordService,
	totpRepo *repository.TOTPRepository,
	eventBus models.EventBus,
	logger models.Logger,
) DisableUseCase {
	return &disableUseCase{
		AccountService:  accountService,
		PasswordService: passwordService,
		TOTPRepo:        totpRepo,
		EventBus:        eventBus,
		Logger:          logger,
	}
}

func (uc *disableUseCase) Disable(ctx context.Context, userID, password string) error {
	if err := verifyPassword(ctx, uc.AccountService, uc.PasswordService, userID, password); err != nil {
		return err
	}

	existing, err := uc.TOTPRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if existing == nil {
		return constants.ErrTOTPNotEnabled
	}

	if err := uc.TOTPRepo.DeleteByUserID(ctx, userID); err != nil {
		return err
	}

	if err := uc.TOTPRepo.DeleteTrustedDevicesByUserID(ctx, userID); err != nil {
		return err
	}

	publishEvent(uc.EventBus, uc.Logger, constants.EventTOTPDisabled, userID)

	return nil
}
