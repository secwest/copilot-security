package search

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

func Search(db *sqlx.DB, status string) ([]string, error) {
	query := fmt.Sprintf("SELECT secret FROM records WHERE owner = 'alice' AND status = '%s'", status)
	var secrets []string
	if err := db.Select(&secrets, query); err != nil {
		return nil, err
	}
	return secrets, nil
}
