package s3

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Client interface {
	UploadBatch(ctx context.Context, epochID int64, data []byte) (string, error)
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
