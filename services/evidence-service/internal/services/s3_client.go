package services

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Client struct {
	Client *s3.Client
	Bucket string
}

// NewS3Client initializes a new S3 client using environment variables.
func NewS3Client() (*S3Client, error) {
	region := os.Getenv("AWS_REGION")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	bucket := os.Getenv("AWS_S3_BUCKET")

	if region == "" || accessKey == "" || secretKey == "" || bucket == "" {
		return nil, fmt.Errorf("missing AWS configuration in environment variables")
	}

	// Use static credentials for now
	staticProvider := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(staticProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg)

	return &S3Client{
		Client: client,
		Bucket: bucket,
	}, nil
}

// UploadFile uploads a file to S3 and returns the object key.
func (s *S3Client) UploadFile(ctx context.Context, key string, body io.Reader) error {
	_, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
		Body:   body,
	})
	return err
}

// DownloadFile retrieves a file from S3 and returns a ReadCloser.
func (s *S3Client) DownloadFile(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := s.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return result.Body, nil
}
