package gorm

import "database/sql"

type Dialector interface {
	Database() *sql.DB
}

type DB struct {
	database *sql.DB
	query    string
	values   []any
	Error    error
}

func Open(dialector Dialector, _ ...any) (*DB, error) {
	return &DB{database: dialector.Database()}, nil
}

func (db *DB) Raw(query string, values ...any) *DB {
	return &DB{database: db.database, query: query, values: values}
}

func (db *DB) Scan(destination any) *DB {
	result := &DB{database: db.database, query: db.query, values: db.values}
	rows, err := db.database.Query(db.query, db.values...)
	if err != nil {
		result.Error = err
		return result
	}
	defer rows.Close()
	target := destination.(*[]string)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			result.Error = err
			return result
		}
		*target = append(*target, value)
	}
	result.Error = rows.Err()
	return result
}
