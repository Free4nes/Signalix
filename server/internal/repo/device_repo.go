package repo

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/signalix/server/internal/model"
)

// DeviceRepo defines the interface for device repository operations
type DeviceRepo interface {
	Create(ctx context.Context, userID uuid.UUID, deviceName string, identityKeyPub []byte) (model.Device, error)
}

type deviceRepo struct {
	db *sql.DB
}

// NewDeviceRepo creates a new DeviceRepo instance
func NewDeviceRepo(db *sql.DB) DeviceRepo {
	return &deviceRepo{db: db}
}

// Create creates a new device for a user
func (r *deviceRepo) Create(ctx context.Context, userID uuid.UUID, deviceName string, identityKeyPub []byte) (model.Device, error) {
	query := `
		INSERT INTO devices (user_id, device_name, identity_key_pub)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`

	var device model.Device
	var idStr string
	var createdAt time.Time

	err := r.db.QueryRowContext(ctx, query, userID, deviceName, identityKeyPub).Scan(
		&idStr,
		&createdAt,
	)
	if err != nil {
		return model.Device{}, fmt.Errorf("failed to create device: %w", err)
	}

	device.ID, err = uuid.Parse(idStr)
	if err != nil {
		return model.Device{}, fmt.Errorf("failed to parse device ID: %w", err)
	}

	device.UserID = userID
	device.DeviceName = deviceName
	device.IdentityKeyPub = identityKeyPub
	device.CreatedAt = createdAt

	return device, nil
}
