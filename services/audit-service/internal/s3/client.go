package s3

import (
	"audit-service/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

type Client interface {
	GetBatch(ctx context.Context, epochID int64) (*store.BatchManifest, error)
	GetAllBatches(ctx context.Context, maxEpoch int64) ([]*store.BatchManifest, error)
}

type s3Client struct {
	client *awss3.Client
	bucket string
}

func NewClient() Client {
	region := os.Getenv("AWS_REGION")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucket := os.Getenv("AWS_S3_BUCKET")

	if region == "" || accessKey == "" || secretKey == "" || bucket == "" {
		log.Printf("Notice: AWS S3 configuration missing in audit-service. Using local batch storage.")
		return &localBatchStorage{}
	}

	staticProvider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(staticProvider),
	)
	if err != nil {
		log.Printf("Warning: Failed to load AWS config: %v. Using local batch storage.", err)
		return &localBatchStorage{}
	}

	return &s3Client{
		client: awss3.NewFromConfig(cfg),
		bucket: bucket,
	}
}

func (s *s3Client) GetBatch(ctx context.Context, epochID int64) (*store.BatchManifest, error) {
	key := fmt.Sprintf("audit-batches/batch_%08d.json", epochID)
	out, err := s.client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		local := &localBatchStorage{}
		if lm, localErr := local.GetBatch(ctx, epochID); localErr == nil {
			return lm, nil
		}
		return nil, fmt.Errorf("failed to get batch %d from S3: %w", epochID, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch %d body: %w", epochID, err)
	}

	var manifest store.BatchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal batch manifest %d: %w", epochID, err)
	}
	return &manifest, nil
}

func (s *s3Client) GetAllBatches(ctx context.Context, maxEpoch int64) ([]*store.BatchManifest, error) {
	var manifests []*store.BatchManifest
	for ep := int64(1); ep <= maxEpoch; ep++ {
		m, err := s.GetBatch(ctx, ep)
		if err != nil {
			log.Printf("Warning: could not read batch %d: %v", ep, err)
			continue
		}
		manifests = append(manifests, m)
	}
	return manifests, nil
}

type localBatchStorage struct{}

func resolveLocalBatchDir() string {
	candidates := []string{
		"./batches",
		"/app/batches",
		"../batches",
		"../../batches",
	}
	for _, dir := range candidates {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}
	return "./batches"
}

func (l *localBatchStorage) GetBatch(ctx context.Context, epochID int64) (*store.BatchManifest, error) {
	dir := resolveLocalBatchDir()
	filename := filepath.Join(dir, fmt.Sprintf("batch_%08d.json", epochID))
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read local batch %d from %s: %w", epochID, filename, err)
	}

	var manifest store.BatchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal local batch manifest %d: %w", epochID, err)
	}
	return &manifest, nil
}

func (l *localBatchStorage) GetAllBatches(ctx context.Context, maxEpoch int64) ([]*store.BatchManifest, error) {
	var manifests []*store.BatchManifest
	if maxEpoch > 0 {
		for ep := int64(1); ep <= maxEpoch; ep++ {
			m, err := l.GetBatch(ctx, ep)
			if err != nil {
				continue
			}
			manifests = append(manifests, m)
		}
		return manifests, nil
	}

	dir := resolveLocalBatchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return manifests, nil
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			var m store.BatchManifest
			if err := json.Unmarshal(data, &m); err == nil {
				manifests = append(manifests, &m)
			}
		}
	}
	return manifests, nil
}
