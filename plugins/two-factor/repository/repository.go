package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"

	"github.com/GoBetterAuth/go-better-auth/v2/models"
)

type TwoFactorRepository struct {
	db bun.IDB
}

func NewTwoFactorRepository(db bun.IDB) *TwoFactorRepository {
	return &TwoFactorRepository{db: db}
}

// --- TwoFactorRecord operations ---

func (r *TwoFactorRepository) GetByUserID(ctx context.Context, userID string) (*TwoFactorRecord, error) {
	record := new(TwoFactorRecord)
	err := r.db.NewSelect().
		Model(record).
		Where("user_id = ?", userID).
		Scan(ctx)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return record, err
}

func (r *TwoFactorRepository) Create(ctx context.Context, userID, secret, backupCodes string) (*TwoFactorRecord, error) {
	record := &TwoFactorRecord{
		ID:          uuid.New().String(),
		UserID:      userID,
		Secret:      secret,
		BackupCodes: backupCodes,
	}

	_, err := r.db.NewInsert().
		Model(record).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func (r *TwoFactorRepository) UpdateBackupCodes(ctx context.Context, userID, backupCodes string) error {
	_, err := r.db.NewUpdate().
		Model(&TwoFactorRecord{}).
		Set("backup_codes = ?", backupCodes).
		Set("updated_at = ?", time.Now()).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

func (r *TwoFactorRepository) DeleteByUserID(ctx context.Context, userID string) error {
	_, err := r.db.NewDelete().
		Model(&TwoFactorRecord{}).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

// --- TrustedDevice operations ---

func (r *TwoFactorRepository) GetTrustedDeviceByToken(ctx context.Context, token string) (*TrustedDevice, error) {
	device := new(TrustedDevice)
	err := r.db.NewSelect().
		Model(device).
		Where("token = ?", token).
		Scan(ctx)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return device, err
}

func (r *TwoFactorRepository) CreateTrustedDevice(ctx context.Context, userID, token, userAgent string, expiresAt time.Time) (*TrustedDevice, error) {
	device := &TrustedDevice{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     token,
		UserAgent: userAgent,
		ExpiresAt: expiresAt,
	}

	_, err := r.db.NewInsert().
		Model(device).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return device, nil
}

func (r *TwoFactorRepository) RefreshTrustedDevice(ctx context.Context, token string, expiresAt time.Time) error {
	_, err := r.db.NewUpdate().
		Model(&TrustedDevice{}).
		Set("expires_at = ?", expiresAt).
		Where("token = ?", token).
		Exec(ctx)
	return err
}

func (r *TwoFactorRepository) DeleteTrustedDevicesByUserID(ctx context.Context, userID string) error {
	_, err := r.db.NewDelete().
		Model(&TrustedDevice{}).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

func (r *TwoFactorRepository) DeleteExpiredTrustedDevices(ctx context.Context) error {
	_, err := r.db.NewDelete().
		Model(&TrustedDevice{}).
		Where("expires_at < ?", time.Now()).
		Exec(ctx)
	return err
}

// --- User field operations ---

func (r *TwoFactorRepository) SetUserTwoFactorEnabled(ctx context.Context, userID string, enabled bool) error {
	_, err := r.db.NewUpdate().
		Model(&models.User{}).
		Set("two_factor_enabled = ?", enabled).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}
