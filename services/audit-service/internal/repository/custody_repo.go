package repository

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/store"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type custodyRepo struct {
	store *store.Storage
}

func NewCustodyRepo(store *store.Storage) CustodyRepo {
	return &custodyRepo{store: store}
}

// Returns a querier for the database.
func (c *custodyRepo) q(ctx context.Context) store.PgxQuerier {
	tx := store.ExtractTx(ctx)
	if tx != nil {
		return tx // Use the transaction passed down via the context.
	}
	return c.store.Pool // No transaction passed, use the Pool.
}

func (c *custodyRepo) InsertCustodyLog(ctx context.Context, custodyLog store.CustodyLog) error {
	query := `
			INSERT INTO integrity_schema.custody_logs (evidence_id, case_id, user_id, action_type, remarks, action_metadata)
			VALUES (@evidenceID, @caseID, @userID, @actionType, @remarks, @actionMetadata)
		`
	args := pgx.NamedArgs{
		"evidenceID":     custodyLog.EvidenceID,
		"caseID":         custodyLog.CaseID,
		"userID":         custodyLog.UserID,
		"actionType":     custodyLog.ActionType,
		"remarks":        custodyLog.Remarks,
		"actionMetadata": custodyLog.ActionMetadata,
	}

	_, err := c.q(ctx).Exec(ctx, query, args)
	// Send meaningful error to the service layer.
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case cerrors.ErrForeignKeyViolation.Code:
				return cerrors.ErrForeignKeyViolation.Error
			case cerrors.ErrNotNullViolation.Code:
				return cerrors.ErrNotNullViolation.Error
			}
		}
		// Error is either not a pgconn.PgError or the error code does not match the expected error code.

		log.Printf("error: failed to insert custody log, %v", err)
		return fmt.Errorf("error: failed to insert custody log, %w", err)
	}

	return nil
}

func (c *custodyRepo) ListCustodyLogs(ctx context.Context, evidenceID string, caseID string, limit int, offset int) ([]store.CustodyLogDTO, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT 
			c.public_id::text,
			COALESCE(eh.evidence_public_id::text, ''),
			c.evidence_id,
			c.case_id,
			c.user_id,
			COALESCE(a.name, 'UNKNOWN'),
			c.action_metadata,
			c.remarks,
			c.timestamp
		FROM integrity_schema.custody_logs c
		LEFT JOIN integrity_schema.actions a ON c.action_type = a.id
		LEFT JOIN integrity_schema.evidence_hashes eh ON c.evidence_id = eh.evidence_id
		WHERE (@evidenceID = '' OR eh.evidence_public_id::text = @evidenceID OR c.evidence_id::text = @evidenceID)
		  AND (@caseID = '' OR c.case_id::text = @caseID OR EXISTS (SELECT 1 FROM case_schema.cases cs WHERE cs.id = c.case_id AND cs.public_id::text = @caseID))
		ORDER BY c.timestamp DESC
		LIMIT @limit OFFSET @offset
	`

	args := pgx.NamedArgs{
		"evidenceID": evidenceID,
		"caseID":     caseID,
		"limit":      limit,
		"offset":     offset,
	}

	rows, err := c.q(ctx).Query(ctx, query, args)
	if err != nil {
		return nil, fmt.Errorf("failed to query custody logs: %w", err)
	}
	defer rows.Close()

	var logs []store.CustodyLogDTO
	for rows.Next() {
		var l store.CustodyLogDTO
		var metadataJSON []byte
		err := rows.Scan(
			&l.PublicID,
			&l.EvidencePublicID,
			&l.EvidenceID,
			&l.CaseID,
			&l.UserID,
			&l.Action,
			&metadataJSON,
			&l.Remarks,
			&l.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan custody log row: %w", err)
		}
		if len(metadataJSON) > 0 {
			var meta map[string]any
			if err := json.Unmarshal(metadataJSON, &meta); err == nil {
				l.ActionMetadata = meta
				if fn, ok := meta["file_name"].(string); ok {
					l.EvidenceName = fn
				}
				if ct, ok := meta["case_title"].(string); ok {
					l.CaseTitle = ct
				}
				if un, ok := meta["user_name"].(string); ok {
					l.UserName = un
				}
				if cp, ok := meta["case_public_id"].(string); ok {
					l.CasePublicID = cp
				}
				if up, ok := meta["user_public_id"].(string); ok {
					l.UserPublicID = up
				}
			}
		}
		logs = append(logs, l)
	}

	if logs == nil {
		logs = []store.CustodyLogDTO{}
	}

	return logs, nil
}

func (c *custodyRepo) GetCustodyLogByID(ctx context.Context, id string) (*store.CustodyLogDTO, error) {
	query := `
		SELECT 
			c.public_id::text,
			COALESCE(eh.evidence_public_id::text, ''),
			c.evidence_id,
			c.case_id,
			c.user_id,
			COALESCE(a.name, 'UNKNOWN'),
			c.action_metadata,
			c.remarks,
			c.timestamp
		FROM integrity_schema.custody_logs c
		LEFT JOIN integrity_schema.actions a ON c.action_type = a.id
		LEFT JOIN integrity_schema.evidence_hashes eh ON c.evidence_id = eh.evidence_id
		WHERE c.public_id::text = @id OR c.id::text = @id
		LIMIT 1
	`

	args := pgx.NamedArgs{
		"id": id,
	}

	var l store.CustodyLogDTO
	var metadataJSON []byte

	err := c.q(ctx).QueryRow(ctx, query, args).Scan(
		&l.PublicID,
		&l.EvidencePublicID,
		&l.EvidenceID,
		&l.CaseID,
		&l.UserID,
		&l.Action,
		&metadataJSON,
		&l.Remarks,
		&l.Timestamp,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("custody log not found")
		}
		return nil, fmt.Errorf("failed to get custody log by id: %w", err)
	}

	if len(metadataJSON) > 0 {
		var meta map[string]any
		if err := json.Unmarshal(metadataJSON, &meta); err == nil {
			l.ActionMetadata = meta
			if fn, ok := meta["file_name"].(string); ok {
				l.EvidenceName = fn
			}
			if ct, ok := meta["case_title"].(string); ok {
				l.CaseTitle = ct
			}
			if un, ok := meta["user_name"].(string); ok {
				l.UserName = un
			}
			if cp, ok := meta["case_public_id"].(string); ok {
				l.CasePublicID = cp
			}
			if up, ok := meta["user_public_id"].(string); ok {
				l.UserPublicID = up
			}
		}
	}

	return &l, nil
}
