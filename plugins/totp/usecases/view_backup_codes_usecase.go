package usecases

import (
	"context"
	"encoding/json"

	"github.com/GoBetterAuth/go-better-auth/v2/plugins/totp/constants"
)

type ViewBackupCodesUseCase struct {
	TOTPRepo TOTPReadRepository
}

func NewViewBackupCodesUseCase(
	totpRepo TOTPReadRepository,
) *ViewBackupCodesUseCase {
	return &ViewBackupCodesUseCase{
		TOTPRepo: totpRepo,
	}
}

func (uc *ViewBackupCodesUseCase) View(ctx context.Context, userID string) (int, error) {
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
