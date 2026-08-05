package documents

import (
	"os"
	"path/filepath"
	"strings"
)

func ReadRelativeDocument(base string, name string) ([]byte, error) {
	absolute := filepath.Join(base, name)
	relative, err := filepath.Rel(base, absolute)
	if err != nil {
		return nil, err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(filepath.Join(base, relative))
}
