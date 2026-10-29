package main

import (
	"audit-worker/internal/rekor"
	"audit-worker/internal/s3"
	"audit-worker/internal/sequencer"
	"audit-worker/internal/store"
	"audit-worker/internal/worker"
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nats-io/nats.go"
)

func main() {
	godotenv.Load()

	log.Println("Starting Secure Digital Evidence System - Audit Writer Worker...")

	connStr := os.Getenv("DB_CONN_STR")
	if connStr == "" {
		log.Fatal("DB_CONN_STR environment variable is required")
	}

	storage, err := store.NewStorage(connStr)
	if err != nil {
		log.Fatalf("Failed to initialize database storage: %v", err)
	}
	defer storage.Close()

	// Connect to NATS JetStream
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://nats:4222"
	}

	nc, err := nats.Connect(natsURL,
		nats.Timeout(10*time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to connect to NATS at %s: %v", natsURL, err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("Failed to create JetStream context: %v", err)
	}

	// Ensure JetStream stream exists
	streamName := "AUDIT_STREAM"
	subject := "audit.events"
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     streamName,
		Subjects: []string{subject},
		Storage:  nats.FileStorage,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		_, infoErr := js.StreamInfo(streamName)
		if infoErr != nil {
			log.Printf("Warning: failed to ensure JetStream stream: %v", err)
		}
	}

	// Initialize S3 & Rekor clients
	s3Client := s3.NewClient()
	rekorClient, err := rekor.NewRekorClient(os.Getenv("REKOR_URL"))
	if err != nil {
		log.Fatalf("Failed to initialize Rekor client: %v", err)
	}

	// Initialize Sequencer with latest state from database
	seq := sequencer.NewSequencer()
	evidenceHashes, chainTip, latestEpoch, err := storage.LoadLatestState(context.Background())
	if err != nil {
		log.Printf("Warning: could not load latest state from database: %v", err)
	}

	// Reconcile and recover state from immutable S3 batch manifests if epochs exist
	if latestEpoch > 0 {
		log.Printf("Reconciling state from S3 batch manifests up to epoch %d...", latestEpoch)
		s3EvidenceHashes, s3ChainTip, err := s3Client.RecoverStateFromS3(context.Background(), latestEpoch)
		if err != nil {
			log.Printf("Warning: could not recover state from S3 manifests: %v", err)
		} else {
			// Compare and alert on discrepancies; S3 manifests take precedence as source of truth
			for evID, dbHash := range evidenceHashes {
				if s3Hash, ok := s3EvidenceHashes[evID]; ok {
					if dbHash != s3Hash {
						log.Printf("ALERT: Discrepancy detected for evidence %d! DB hash (%s) != S3 manifest hash (%s). Using S3 authoritative hash.",
							evID, dbHash, s3Hash)
					}
				}
			}
			for evID, s3Hash := range s3EvidenceHashes {
				evidenceHashes[evID] = s3Hash
			}
			if s3ChainTip != "" {
				if chainTip != "" && chainTip != s3ChainTip {
					log.Printf("ALERT: Global chain tip discrepancy! DB tip (%s) != S3 tip (%s). Using S3 authoritative tip.", chainTip, s3ChainTip)
				}
				chainTip = s3ChainTip
			}
			log.Printf("State successfully reconciled with S3: %d evidence streams tracked", len(evidenceHashes))
		}
	}

	seq.InitializeState(evidenceHashes, chainTip)

	// Configure batch parameters
	batchSize := 100
	if bsStr := os.Getenv("BATCH_SIZE"); bsStr != "" {
		if bs, err := strconv.Atoi(bsStr); err == nil && bs > 0 {
			batchSize = bs
		}
	}

	batchInterval := 20 * time.Minute
	if biStr := os.Getenv("BATCH_INTERVAL_MINUTES"); biStr != "" {
		if bi, err := strconv.Atoi(biStr); err == nil && bi > 0 {
			batchInterval = time.Duration(bi) * time.Minute
		}
	}

	w := worker.NewWorker(
		seq,
		storage,
		s3Client,
		rekorClient,
		js,
		latestEpoch,
		batchSize,
		batchInterval,
	)

	if err := w.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start worker: %v", err)
	}

	log.Println("Audit Writer Worker running. Awaiting audit events...")

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received. Stopping worker and flushing uncommitted batches...")
	w.Stop()
	log.Println("Audit Writer Worker stopped gracefully.")
}
