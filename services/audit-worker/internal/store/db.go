package store

import (
	"audit-worker/internal/models"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func NewStorage(connStr string) (*Storage, error) {
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DB connection string: %w", err)
	}

	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Storage{pool: pool}, nil
}

func (s *Storage) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// LoadLatestState retrieves the latest current_hash for each evidence and the global chain tip.
func (s *Storage) LoadLatestState(ctx context.Context) (map[int64]string, string, int64, error) {
	evidenceMap := make(map[int64]string)
	var globalChainTip string
	var latestEpochID int64

	// 1. Get latest hash per evidence_id
	query := `
		SELECT evidence_id, current_hash
		FROM integrity_schema.audit_logs
		WHERE id IN (
			SELECT MAX(id)
			FROM integrity_schema.audit_logs
			GROUP BY evidence_id
		)
	`
	rows, err := s.pool.Query(ctx, query)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var evID int64
			var h string
			if err := rows.Scan(&evID, &h); err == nil {
				evidenceMap[evID] = h
			}
		}
	}

	// 2. Get overall latest hash
	tipQuery := `
		SELECT current_hash
		FROM integrity_schema.audit_logs
		ORDER BY id DESC
		LIMIT 1
	`
	_ = s.pool.QueryRow(ctx, tipQuery).Scan(&globalChainTip)

	// 3. Get latest epoch_id
	epochQuery := `
		SELECT COALESCE(MAX(epoch_id), 0)
		FROM integrity_schema.audit_anchors
	`
	_ = s.pool.QueryRow(ctx, epochQuery).Scan(&latestEpochID)

	log.Printf("Loaded state from DB: %d active evidence streams, global chain tip: %s, latest epoch: %d",
		len(evidenceMap), globalChainTip, latestEpochID)

	return evidenceMap, globalChainTip, latestEpochID, nil
}

// InsertAuditLogs inserts a batch of audit logs and returns their inserted IDs.
func (s *Storage) InsertAuditLogs(ctx context.Context, records []models.AuditLogRecord) ([]int64, error) {
	if len(records) == 0 {
		return nil, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	insertedIDs := make([]int64, len(records))

	query := `
		INSERT INTO integrity_schema.audit_logs (
			user_id, case_id, evidence_id, action_type, service_name, ip_address,
			previous_hash, current_hash, request_id, status, details, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`

	for i, r := range records {
		var id int64
		var detailsJSON any = nil
		if r.Details != "" {
			detailsJSON = []byte(r.Details)
		}

		err := tx.QueryRow(ctx, query,
			r.UserID,
			r.CaseID,
			r.EvidenceID,
			r.ActionType,
			r.ServiceName,
			r.IPAddress,
			r.PreviousHash,
			r.CurrentHash,
			r.RequestID,
			r.Status,
			detailsJSON,
			r.CreatedAt,
		).Scan(&id)

		if err != nil {
			return nil, fmt.Errorf("failed to insert audit log record %d: %w", i, err)
		}
		insertedIDs[i] = id
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit audit logs batch: %w", err)
	}

	return insertedIDs, nil
}

// InsertAnchor saves the Rekor transparency anchor into integrity_schema.audit_anchors.
func (s *Storage) InsertAnchor(ctx context.Context, anchor models.AuditAnchor) error {
	query := `
		INSERT INTO integrity_schema.audit_anchors (
			epoch_id, start_log_id, end_log_id, event_count, merkle_root, chain_tip,
			s3_key, rekor_log_index, rekor_entry_uuid, rekor_integrated_time, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (epoch_id) DO UPDATE SET
			rekor_entry_uuid = EXCLUDED.rekor_entry_uuid,
			rekor_log_index = EXCLUDED.rekor_log_index,
			rekor_integrated_time = EXCLUDED.rekor_integrated_time
	`

	created := anchor.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}

	_, err := s.pool.Exec(ctx, query,
		anchor.EpochID,
		anchor.StartLogID,
		anchor.EndLogID,
		anchor.EventCount,
		anchor.MerkleRoot,
		anchor.ChainTip,
		anchor.S3Key,
		anchor.RekorLogIndex,
		anchor.RekorEntryUUID,
		anchor.RekorIntegratedTime,
		created,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit anchor: %w", err)
	}

	log.Printf("Recorded audit anchor for epoch %d (Rekor UUID: %s, LogIndex: %d)",
		anchor.EpochID, anchor.RekorEntryUUID, anchor.RekorLogIndex)
	return nil
}
