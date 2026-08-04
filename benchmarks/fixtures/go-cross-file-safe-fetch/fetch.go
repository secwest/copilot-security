package preview

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var destinations = map[string]string{
	"status": "https://status.example.invalid/health",
}

func Fetch(ctx context.Context, destination string) (*http.Response, error) {
	target, ok := destinations[destination]
	if !ok {
		return nil, errors.New("unknown destination")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client.Do(request)
}
