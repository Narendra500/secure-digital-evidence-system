package service

import (
	"context"
	"io"
)

type FileFetcher interface {
	GetFile(ctx context.Context, evidenceID string) (io.ReadCloser, error)
}
