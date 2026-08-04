package sqlx

import "database/sql"

type DB struct {
	*sql.DB
}

func NewDb(database *sql.DB, _ string) *DB {
	return &DB{DB: database}
}

func (db *DB) Select(destination any, query string, arguments ...any) error {
	target := destination.(*[]string)
	rows, err := db.Query(query, arguments...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return err
		}
		*target = append(*target, value)
	}
	return rows.Err()
}
