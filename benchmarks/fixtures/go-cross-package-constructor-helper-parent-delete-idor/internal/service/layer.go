package service

type repositoryLayer struct {
	repository InvoiceRepository
	label      string
}

func newRepositoryLayer(label string) *repositoryLayer {
	layer := &repositoryLayer{label: label}
	selected := layer
	return selected
}
