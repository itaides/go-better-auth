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

type verifyBackupCodeUseCase struct {
	TokenService        rootservices.TokenService
	SessionService      rootservices.SessionService
	UserService         rootservices.UserService
	VerificationService rootservices.VerificationService
	BackupCodeService   *services.BackupCodeService
	TOTPRepo            *repository.TOTPRepository
	GlobalConfig        *models.Config
	Config              *types.TOTPPluginConfig
	EventBus            models.EventBus
	Logger              models.Logger
}

func NewVerifyBackupCodeUseCase(
	tokenService rootservices.TokenService,
	sessionService rootservices.SessionService,
	userService rootservices.UserService,
	verificationService rootservices.VerificationService,
	backupCodeService *services.BackupCodeService,
	totpRepo *repository.TOTPRepository,
	globalConfig *models.Config,
	config *types.TOTPPluginConfig,
	eventBus models.EventBus,
	logger models.Logger,
) VerifyBackupCodeUseCase {
	return &verifyBackupCodeUseCase{
		TokenService:        tokenService,
		SessionService:      sessionService,
		UserService:         userService,
		VerificationService: verificationService,
		BackupCodeService:   backupCodeService,
		TOTPRepo:            totpRepo,
		GlobalConfig:        globalConfig,
		Config:              config,
		EventBus:            eventBus,
		Logger:              logger,
	}
}

func (uc *verifyBackupCodeUseCase) Verify(ctx context.Context, pendingToken, code string, trustDevice bool, ipAddress, userAgent *string) (*types.VerifyResult, error) {
	userID, verificationID, err := resolvePendingToken(ctx, uc.TokenService, uc.VerificationService, pendingToken)
	if err != nil {
		return nil, err
	}

	record, err := uc.TOTPRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, constants.ErrTOTPNotEnabled
	}

	var hashedCodes []string
	if err := json.Unmarshal([]byte(record.BackupCodes), &hashedCodes); err != nil {
		return nil, err
	}

	remaining, valid := uc.BackupCodeService.VerifyAndConsume(hashedCodes, code)
	if !valid {
		return nil, constants.ErrInvalidBackupCode
	}

	remainingJSON, err := json.Marshal(remaining)
	if err != nil {
		return nil, err
	}
	if err := uc.TOTPRepo.UpdateBackupCodes(ctx, userID, string(remainingJSON)); err != nil {
		return nil, err
	}

	user, err := uc.UserService.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, constants.ErrUserNotFound
	}

	session, token, err := createSessionForUser(ctx, uc.TokenService, uc.SessionService, uc.VerificationService, uc.GlobalConfig, userID, verificationID, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	result := &types.VerifyResult{
		User:         user,
		Session:      session,
		SessionToken: token,
	}

	if trustDevice {
		deviceToken, err := createTrustedDevice(ctx, uc.TokenService, uc.TOTPRepo, uc.Config, userID, userAgent)
		if err != nil {
			return nil, err
		}
		result.TrustedDeviceToken = deviceToken

		publishEvent(uc.EventBus, uc.Logger, constants.EventTOTPDeviceTrusted, userID)
	}

	publishEvent(uc.EventBus, uc.Logger, constants.EventTOTPBackupUsed, userID)

	return result, nil
}
