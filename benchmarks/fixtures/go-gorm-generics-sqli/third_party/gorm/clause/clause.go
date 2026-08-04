package clause

// Expression is the option boundary used by GORM's generic constructor.
type Expression interface {
	Build(Builder)
}

// Builder is intentionally minimal because the benchmark does not interpret options.
type Builder interface{}
