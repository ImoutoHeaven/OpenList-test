package db

import (
	"context"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

func GetGoogleDriveAccountHealthContextOn(ctx context.Context, database *gorm.DB, accountKey string) (*model.GoogleDriveAccountHealth, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var state model.GoogleDriveAccountHealth
	if database == nil {
		return nil, errors.New("database is not initialized")
	}
	if err := database.WithContext(ctx).Where("account_key = ?", accountKey).First(&state).Error; err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.WithStack(err)
	}
	return &state, nil
}

func SaveGoogleDriveAccountHealthContextOn(ctx context.Context, database *gorm.DB, state *model.GoogleDriveAccountHealth) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if database == nil {
		return errors.New("database is not initialized")
	}
	err := database.WithContext(ctx).Save(state).Error
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return errors.WithStack(err)
}
