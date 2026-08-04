package search

import "github.com/jmoiron/sqlx"

func Search(db *sqlx.DB, status string) ([]string, error) {
	const query = "SELECT secret FROM records WHERE owner = 'alice' AND status = ?"
	var secrets []string
	if err := db.Select(&secrets, query, status); err != nil {
		return nil, err
	}
	return secrets, nil
}
