package service

import (
	"audit-service/internal/cerrors"
	"context"
	"fmt"
	"io"
	"net/http"
)

type fileFetcher struct {
	baseURL string
	client  *http.Client
}

func NewFileFetcher(baseURL string, client *http.Client) FileFetcher {
	return &fileFetcher{baseURL, client}
}

func (f *fileFetcher) GetFile(ctx context.Context, evidenceID string) (io.ReadCloser, error) {
	url := fmt.Sprintf("%s/evidence/%s/file", f.baseURL, evidenceID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp.Body, nil
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, cerrors.ErrFileNotFound.Error
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
