package search

import "gorm.io/gorm"

func Search(db *gorm.DB, status string) ([]string, error) {
	const query = "SELECT secret FROM records WHERE owner = 'alice' AND status = ?"
	var secrets []string
	result := db.Raw(query, status).Scan(&secrets)
	return secrets, result.Error
}
