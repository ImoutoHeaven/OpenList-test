package db

import (
	"context"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func GetGoogleDriveQuotaAuthorityContextOn(ctx context.Context, database *gorm.DB, key string) (*model.GoogleDriveQuotaAuthority, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if database == nil {
		return nil, errors.New("database is not initialized")
	}
	var state model.GoogleDriveQuotaAuthority
	if err := database.WithContext(ctx).Where("key = ?", key).First(&state).Error; err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.WithStack(err)
	}
	return &state, nil
}

func SaveGoogleDriveQuotaAuthorityContextOn(ctx context.Context, database *gorm.DB, state *model.GoogleDriveQuotaAuthority) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if database == nil {
		return errors.New("database is not initialized")
	}
	if state == nil || state.Key == "" {
		return errors.New("quota authority state is required")
	}
	if err := database.WithContext(ctx).Save(state).Error; err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.WithStack(err)
	}
	return nil
}
