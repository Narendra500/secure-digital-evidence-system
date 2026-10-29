package s3

import (
	"audit-worker/internal/models"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Client interface {
	UploadBatch(ctx context.Context, epochID int64, data []byte) (string, error)
	GetBatch(ctx context.Context, epochID int64) (*models.BatchManifest, error)
	FindLatestHashForEvidence(ctx context.Context, evidenceID int64, latestEpoch int64) (string, bool, error)
	RecoverStateFromS3(ctx context.Context, latestEpoch int64) (map[int64]string, string, error)
}

type s3Client struct {
	client *s3.Client
	bucket string
}

func NewClient() Client {
	region := os.Getenv("AWS_REGION")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucket := os.Getenv("AWS_S3_BUCKET")

	if region == "" || accessKey == "" || secretKey == "" || bucket == "" {
		log.Printf("Warning: AWS S3 configuration missing. Using local batch storage.")
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
		client: s3.NewFromConfig(cfg),
		bucket: bucket,
	}
}

func (s *s3Client) UploadBatch(ctx context.Context, epochID int64, data []byte) (string, error) {
	key := fmt.Sprintf("audit-batches/batch_%08d.json", epochID)

	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload batch to S3: %w", err)
	}

	log.Printf("Uploaded batch epoch %d to S3: s3://%s/%s", epochID, s.bucket, key)
	return fmt.Sprintf("s3://%s/%s", s.bucket, key), nil
}

func (s *s3Client) GetBatch(ctx context.Context, epochID int64) (*models.BatchManifest, error) {
	key := fmt.Sprintf("audit-batches/batch_%08d.json", epochID)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get batch %d from S3: %w", epochID, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read batch %d body: %w", epochID, err)
	}

	var manifest models.BatchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal batch manifest %d: %w", epochID, err)
	}
	return &manifest, nil
}

func (s *s3Client) FindLatestHashForEvidence(ctx context.Context, evidenceID int64, latestEpoch int64) (string, bool, error) {
	for ep := latestEpoch; ep >= 1; ep-- {
		manifest, err := s.GetBatch(ctx, ep)
		if err != nil {
			continue
		}
		for i := len(manifest.Events) - 1; i >= 0; i-- {
			if manifest.Events[i].EvidenceID == evidenceID {
				return manifest.Events[i].CurrentHash, true, nil
			}
		}
	}
	return "", false, nil
}

func (s *s3Client) RecoverStateFromS3(ctx context.Context, latestEpoch int64) (map[int64]string, string, error) {
	state := make(map[int64]string)
	var globalTip string

	for ep := latestEpoch; ep >= 1; ep-- {
		manifest, err := s.GetBatch(ctx, ep)
		if err != nil {
			log.Printf("Warning: could not read batch manifest %d from S3: %v", ep, err)
			continue
		}
		if globalTip == "" && manifest.ChainTip != "" {
			globalTip = manifest.ChainTip
		}
		for i := len(manifest.Events) - 1; i >= 0; i-- {
			evID := manifest.Events[i].EvidenceID
			if _, exists := state[evID]; !exists {
				state[evID] = manifest.Events[i].CurrentHash
			}
		}
	}
	return state, globalTip, nil
}

type localBatchStorage struct{}

func (l *localBatchStorage) UploadBatch(ctx context.Context, epochID int64, data []byte) (string, error) {
	dir := "./batches"
	_ = os.MkdirAll(dir, 0755)
	filename := fmt.Sprintf("%s/batch_%08d.json", dir, epochID)
	err := os.WriteFile(filename, data, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write local batch file: %w", err)
	}
	log.Printf("Saved batch epoch %d locally: %s", epochID, filename)
	return filename, nil
}

func (l *localBatchStorage) GetBatch(ctx context.Context, epochID int64) (*models.BatchManifest, error) {
	dir := "./batches"
	filename := fmt.Sprintf("%s/batch_%08d.json", dir, epochID)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read local batch %d: %w", epochID, err)
	}

	var manifest models.BatchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal local batch manifest %d: %w", epochID, err)
	}
	return &manifest, nil
}

func (l *localBatchStorage) FindLatestHashForEvidence(ctx context.Context, evidenceID int64, latestEpoch int64) (string, bool, error) {
	for ep := latestEpoch; ep >= 1; ep-- {
		manifest, err := l.GetBatch(ctx, ep)
		if err != nil {
			continue
		}
		for i := len(manifest.Events) - 1; i >= 0; i-- {
			if manifest.Events[i].EvidenceID == evidenceID {
				return manifest.Events[i].CurrentHash, true, nil
			}
		}
	}
	return "", false, nil
}

func (l *localBatchStorage) RecoverStateFromS3(ctx context.Context, latestEpoch int64) (map[int64]string, string, error) {
	state := make(map[int64]string)
	var globalTip string

	for ep := latestEpoch; ep >= 1; ep-- {
		manifest, err := l.GetBatch(ctx, ep)
		if err != nil {
			continue
		}
		if globalTip == "" && manifest.ChainTip != "" {
			globalTip = manifest.ChainTip
		}
		for i := len(manifest.Events) - 1; i >= 0; i-- {
			evID := manifest.Events[i].EvidenceID
			if _, exists := state[evID]; !exists {
				state[evID] = manifest.Events[i].CurrentHash
			}
		}
	}
	return state, globalTip, nil
}
