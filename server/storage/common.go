package storage

import (
	"context"
	"fmt"
	"io"
)

// Storage is the interface for storage operation
type Storage interface {
	// Get retrieves a file from storage
	Get(ctx context.Context, filename string) (reader io.ReadCloser, contentLength uint64, err error)
	// Head retrieves content length of a file from storage
	Head(ctx context.Context, filename string) (contentLength uint64, err error)
	// Put saves a file on storage
	Put(ctx context.Context, filename string, reader io.Reader) error
	// Delete removes a file from storage
	Delete(ctx context.Context, filename string) error
	// IsNotExist indicates if a file doesn't exist on storage
	IsNotExist(err error) bool

	// Type returns the storage type
	Type() string
}

func CloseCheck(f func() error) {
	if err := f(); err != nil {
		fmt.Println("Received close error:", err)
	}
}
