package repository

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/store"
	"context"
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
