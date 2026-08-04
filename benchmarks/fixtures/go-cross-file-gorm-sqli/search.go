package search

import (
	"fmt"

	"gorm.io/gorm"
)

func Search(db *gorm.DB, status string) ([]string, error) {
	query := fmt.Sprintf("SELECT secret FROM records WHERE owner = 'alice' AND status = '%s'", status)
	var secrets []string
	result := db.Raw(query).Scan(&secrets)
	return secrets, result.Error
}
