package documents

import (
	"io"
	"os"
)

func ReadDocument(base string, name string) ([]byte, error) {
	file, err := os.OpenInRoot(base, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}
