package documents

import (
	"os"
	"path/filepath"
)

func ReadDocument(base string, name string) ([]byte, error) {
	path := filepath.Join(base, name)
	return os.ReadFile(path)
}
