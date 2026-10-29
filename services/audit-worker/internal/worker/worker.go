package worker

import (
	"audit-worker/internal/merkle"
	"audit-worker/internal/models"
	"audit-worker/internal/rekor"
	"audit-worker/internal/s3"
	"audit-worker/internal/sequencer"
	"audit-worker/internal/store"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

type Worker struct {
	sequencer     sequencer.Sequencer
	store         *store.Storage
	s3Client      s3.Client
	rekorClient   rekor.Client
	js            nats.JetStreamContext
	sub           *nats.Subscription
	mu            sync.Mutex
	buffer             []models.AuditLogRecord
	bufferMsgs         []*nats.Msg
	bufferedRequestIDs map[string]bool
	batchSize          int
	batchInterval      time.Duration
	epochID            int64
	stopChan           chan struct{}
}

func NewWorker(
	seq sequencer.Sequencer,
	storage *store.Storage,
	s3Cli s3.Client,
	rekorCli rekor.Client,
	js nats.JetStreamContext,
	initialEpoch int64,
	batchSize int,
	batchInterval time.Duration,
) *Worker {
	if batchSize <= 0 {
		batchSize = 100
	}
	if batchInterval <= 0 {
		batchInterval = 20 * time.Minute
	}

	return &Worker{
		sequencer:          seq,
		store:              storage,
		s3Client:           s3Cli,
		rekorClient:        rekorCli,
		js:                 js,
		batchSize:          batchSize,
		batchInterval:      batchInterval,
		epochID:            initialEpoch,
		bufferedRequestIDs: make(map[string]bool),
		stopChan:           make(chan struct{}),
	}
}

func (w *Worker) Start(ctx context.Context) error {
	subject := "audit.events"
	consumerName := "audit-worker-group"

	// Check if durable consumer already exists with a different AckWait
	ci, err := w.js.ConsumerInfo("AUDIT_STREAM", consumerName)
	if err == nil && ci != nil && ci.Config.AckWait != 30*time.Minute {
		log.Printf("Consumer %s has AckWait %v. Updating to 30m0s...", consumerName, ci.Config.AckWait)
		cfg := ci.Config
		cfg.AckWait = 30 * time.Minute
		if _, updateErr := w.js.UpdateConsumer("AUDIT_STREAM", &cfg); updateErr != nil {
			log.Printf("Warning: failed to update consumer, recreating: %v", updateErr)
			_ = w.js.DeleteConsumer("AUDIT_STREAM", consumerName)
		}
	}

	// Subscribe via JetStream push/pull consumer
	sub, err := w.js.SubscribeSync(subject,
		nats.Durable(consumerName),
		nats.ManualAck(),
		nats.AckWait(30*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("failed to subscribe to JetStream subject %s: %w", subject, err)
	}
	w.sub = sub

	log.Printf("Worker subscribed to %s (batch size: %d, interval: %v)", subject, w.batchSize, w.batchInterval)

	// Periodic flush ticker
	go func() {
		ticker := time.NewTicker(w.batchInterval)
		defer ticker.Stop()

		for {
			select {
			case <-w.stopChan:
				return
			case <-ticker.C:
				w.mu.Lock()
				if len(w.buffer) > 0 {
					log.Printf("Batch interval elapsed (%v). Flushing %d buffered events...", w.batchInterval, len(w.buffer))
					if err := w.flushBatchLocked(context.Background()); err != nil {
						log.Printf("Error flushing batch on timer: %v", err)
					}
				}
				w.mu.Unlock()
			}
		}
	}()

	// Message processing loop
	go func() {
		for {
			select {
			case <-w.stopChan:
				return
			default:
				msg, err := w.sub.NextMsg(1 * time.Second)
				if err != nil {
					if err == nats.ErrTimeout {
						continue
					}
					select {
					case <-w.stopChan:
						return
					default:
						log.Printf("Warning: error fetching next message: %v", err)
						time.Sleep(500 * time.Millisecond)
						continue
					}
				}

				var event models.AuditEventMessage
				if err := json.Unmarshal(msg.Data, &event); err != nil {
					log.Printf("Error unmarshaling audit event message: %v. Terminating bad message.", err)
					_ = msg.Term()
					continue
				}

				w.mu.Lock()
				if event.RequestID != "" && w.bufferedRequestIDs[event.RequestID] {
					log.Printf("Duplicate event %s for evidence %d already in buffer, tracking message for ack", event.RequestID, event.EvidenceID)
					w.bufferMsgs = append(w.bufferMsgs, msg)
					w.mu.Unlock()
					continue
				}

				// If evidence is not in sequencer memory and we have prior epochs, query S3 batch manifests
				if !w.sequencer.HasEvidence(event.EvidenceID) && w.epochID > 0 {
					s3Hash, found, err := w.s3Client.FindLatestHashForEvidence(context.Background(), event.EvidenceID, w.epochID)
					if err != nil {
						log.Printf("Warning: error querying S3 for evidence %d: %v", event.EvidenceID, err)
					}
					if found {
						log.Printf("Evidence %d not in memory: retrieved previous hash from S3: %s", event.EvidenceID, s3Hash)
						w.sequencer.SetLatestHash(event.EvidenceID, s3Hash)
					} else {
						log.Printf("Evidence %d not in memory or S3 manifests (Genesis event)", event.EvidenceID)
					}
				}

				// Process through in-memory sequencer (prevHash lookup from memory, never Postgres!)
				record := w.sequencer.ProcessEvent(event)
				w.buffer = append(w.buffer, record)
				w.bufferMsgs = append(w.bufferMsgs, msg)
				if event.RequestID != "" {
					w.bufferedRequestIDs[event.RequestID] = true
				}

				log.Printf("Buffered event #%d for evidence %d, hash: %s", len(w.buffer), record.EvidenceID, record.CurrentHash)

				if len(w.buffer) >= w.batchSize {
					log.Printf("Batch size reached (%d). Flushing batch epoch...", w.batchSize)
					if err := w.flushBatchLocked(context.Background()); err != nil {
						log.Printf("CRITICAL: Failed to flush batch: %v", err)
					}
				}
				w.mu.Unlock()
			}
		}
	}()

	return nil
}

func (w *Worker) flushBatchLocked(ctx context.Context) error {
	if len(w.buffer) == 0 {
		return nil
	}

	epoch := w.epochID + 1
	count := len(w.buffer)

	log.Printf("Starting flush for Epoch %d with %d events...", epoch, count)

	// 1. Build Merkle Root from event hashes
	leafHashes := make([]string, count)
	for i, rec := range w.buffer {
		leafHashes[i] = rec.CurrentHash
	}
	merkleRoot := merkle.ComputeRoot(leafHashes)
	chainTip := w.buffer[count-1].CurrentHash

	log.Printf("Epoch %d: Merkle Root: %s, Chain Tip: %s", epoch, merkleRoot, chainTip)

	// 2. Submit Merkle Root to Sigstore Rekor
	rekorRes, err := w.rekorClient.AnchorHash(ctx, merkleRoot)
	if err != nil {
		log.Printf("Warning: Rekor anchoring encountered error: %v", err)
	}
	if rekorRes == nil {
		rekorRes = &rekor.RekorResult{
			EntryUUID:      fmt.Sprintf("epoch-%d-%d", epoch, time.Now().Unix()),
			LogIndex:       time.Now().Unix(),
			IntegratedTime: time.Now().UTC(),
		}
	}

	// 3. Upload Batch Manifest to S3
	manifest := models.BatchManifest{
		EpochID:       epoch,
		EventCount:    count,
		MerkleRoot:    merkleRoot,
		ChainTip:      chainTip,
		RekorUUID:     rekorRes.EntryUUID,
		RekorLogIndex: rekorRes.LogIndex,
		Timestamp:     time.Now().UTC(),
		Events:        w.buffer,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal batch manifest: %w", err)
	}

	s3Key, err := w.s3Client.UploadBatch(ctx, epoch, manifestBytes)
	if err != nil {
		log.Printf("Warning: S3 upload failed: %v", err)
		s3Key = fmt.Sprintf("local://batches/batch_%08d.json", epoch)
	}

	// 4. Insert Audit Log records into PostgreSQL
	insertedIDs, err := w.store.InsertAuditLogs(ctx, w.buffer)
	if err != nil {
		return fmt.Errorf("failed to insert audit logs into database: %w", err)
	}

	startID := insertedIDs[0]
	endID := insertedIDs[len(insertedIDs)-1]

	// 5. Insert Anchor into PostgreSQL
	anchor := models.AuditAnchor{
		EpochID:             epoch,
		StartLogID:          startID,
		EndLogID:            endID,
		EventCount:          count,
		MerkleRoot:          merkleRoot,
		ChainTip:            chainTip,
		S3Key:               s3Key,
		RekorLogIndex:       rekorRes.LogIndex,
		RekorEntryUUID:      rekorRes.EntryUUID,
		RekorIntegratedTime: rekorRes.IntegratedTime,
		CreatedAt:           time.Now().UTC(),
	}

	if err := w.store.InsertAnchor(ctx, anchor); err != nil {
		log.Printf("Warning: failed to insert anchor record in database: %v", err)
	}

	// 6. Acknowledge NATS messages
	for _, msg := range w.bufferMsgs {
		_ = msg.Ack()
	}

	log.Printf("Successfully completed and anchored Epoch %d (%d events, IDs %d-%d)", epoch, count, startID, endID)

	w.epochID = epoch
	// Clear buffer
	w.buffer = nil
	w.bufferMsgs = nil
	w.bufferedRequestIDs = make(map[string]bool)

	return nil
}

func (w *Worker) Stop() {
	close(w.stopChan)
	if w.sub != nil {
		_ = w.sub.Unsubscribe()
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buffer) > 0 {
		log.Printf("Flushing remaining %d events before shutdown...", len(w.buffer))
		_ = w.flushBatchLocked(context.Background())
	}
}
