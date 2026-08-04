package search

import (
	"database/sql"
	"fmt"

	sq "github.com/Masterminds/squirrel"
)

func Search(db *sql.DB, status string) ([]string, error) {
	predicate := fmt.Sprintf("owner = 'alice' AND status = '%s'", status)
	rows, err := sq.Select("secret").From("records").Where(predicate).RunWith(db).Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets []string
	for rows.Next() {
		var secret string
		if err := rows.Scan(&secret); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}
	return secrets, rows.Err()
}
