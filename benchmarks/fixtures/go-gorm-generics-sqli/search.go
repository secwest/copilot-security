package search

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

func Search(ctx context.Context, db *gorm.DB, status string) ([]string, error) {
	predicate := fmt.Sprintf("owner = 'alice' AND status = '%s'", status)
	return gorm.G[string](db).Where(predicate).Find(ctx)
}
