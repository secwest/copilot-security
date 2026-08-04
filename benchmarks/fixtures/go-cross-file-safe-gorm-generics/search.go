package search

import (
	"context"

	"gorm.io/gorm"
)

func Search(ctx context.Context, db *gorm.DB, status string) ([]string, error) {
	return gorm.G[string](db).Where("owner = 'alice' AND status = ?", status).Find(ctx)
}
