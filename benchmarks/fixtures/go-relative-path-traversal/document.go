package documents

import (
	"os"
	"path/filepath"
)

func ReadRelativeDocument(base string, name string) ([]byte, error) {
	absolute := filepath.Join(base, name)
	relative, err := filepath.Rel(base, absolute)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(base, relative))
}
