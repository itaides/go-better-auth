package usecases

import (
	"context"
	"encoding/json"

	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/repository"
	rootservices "github.com/GoBetterAuth/go-better-auth/v2/services"
)

type viewBackupCodesUseCase struct {
	AccountService  rootservices.AccountService
	PasswordService rootservices.PasswordService
	TOTPRepo        *repository.TOTPRepository
}

func NewViewBackupCodesUseCase(
	accountService rootservices.AccountService,
	passwordService rootservices.PasswordService,
	totpRepo *repository.TOTPRepository,
) ViewBackupCodesUseCase {
	return &viewBackupCodesUseCase{
		AccountService:  accountService,
		PasswordService: passwordService,
		TOTPRepo:        totpRepo,
	}
}

func (uc *viewBackupCodesUseCase) View(ctx context.Context, userID, password string) (int, error) {
	if err := verifyPassword(ctx, uc.AccountService, uc.PasswordService, userID, password); err != nil {
		return 0, err
	}

	record, err := uc.TOTPRepo.GetByUserID(ctx, userID)
	if err != nil {
		return 0, err
	}
	if record == nil {
		return 0, constants.ErrTOTPNotEnabled
	}

	var hashedCodes []string
	if err := json.Unmarshal([]byte(record.BackupCodes), &hashedCodes); err != nil {
		return 0, err
	}

	return len(hashedCodes), nil
}
