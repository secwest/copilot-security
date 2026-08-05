package service

import store "example.com/go-cross-package-promoted-method-delete-idor/internal/store"

type RepositoryLayer struct {
	*store.Store
}

type Service struct {
	RepositoryLayer
}

func NewService(repository *store.Store) *Service {
	return &Service{RepositoryLayer: RepositoryLayer{Store: repository}}
}
