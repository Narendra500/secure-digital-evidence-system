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

type evidenceRepo struct {
	store *store.Storage
}

func NewEvidenceRepo(store *store.Storage) EvidenceRepo {
	return &evidenceRepo{store: store}
}

// Returns a querier for the database.
func (r *evidenceRepo) q(ctx context.Context) store.PgxQuerier {
	tx := store.ExtractTx(ctx)
	if tx != nil {
		return tx // Use the transaction passed down via the context.
	}
	return r.store.Pool // No transaction passed, use the Pool.
}

// Inserts a new evidence hash into the database.
func (r *evidenceRepo) InsertEvidenceHash(ctx context.Context, e store.EvidenceDetails) error {
	query := `
			INSERT INTO integrity_schema.evidence_hashes (evidence_id, evidence_public_ic, file_hash, algorithm)
			VALUES (@evidenceID, @evidencePublicID, @fileHash, @algorithm)
		`

	args := pgx.NamedArgs{
		"evidenceID":       e.EvidenceID,
		"evidencePublicID": e.EvidencePublicID,
		"fileHash":         e.FileHash,
		"algorithm":        e.Algorithm,
	}

	// Call r.q(ctx) instead of r.db to use the transaction if one is passed down via the context.
	_, err := r.q(ctx).Exec(ctx, query, args)
	// Send meaningful error to the service layer.
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case cerrors.ErrEvidenceAlreadyExists.Code:
				return cerrors.ErrEvidenceAlreadyExists.Error
			case cerrors.ErrNotNullViolation.Code:
				return cerrors.ErrNotNullViolation.Error
			case cerrors.ErrForeignKeyViolation.Code:
				return cerrors.ErrForeignKeyViolation.Error
			}
		}
		// Error is either not a pgconn.PgError or the error code does not match the expected error code.
		log.Printf("error: failed to insert evidence hash, %v", err)
		return fmt.Errorf("error: failed to insert evidence hash, %w", err)
	}

	return nil
}

// Gets the file hash and algorithm for a given evidence ID.
func (r *evidenceRepo) GetEvidenceHash(ctx context.Context, evidenceID string) (*store.EvidenceHash, error) {
	var e store.EvidenceHash
	query := `
		SELECT file_hash, algorithm
		FROM integrity_schema.evidence_hashes
		WHERE evidence_id = @evidenceID
	`

	args := pgx.NamedArgs{
		"evidenceID": evidenceID,
	}

	if err := r.q(ctx).QueryRow(ctx, query, args).Scan(&e.FileHash, &e.Algorithm); err != nil {
		if err == pgx.ErrNoRows {
			return nil, cerrors.ErrEvidenceNotFound.Error
		}
		log.Printf("error: failed to get evidence hash, %v", err)
		return nil, fmt.Errorf("error: failed to get evidence hash, %w", err)
	}

	return &e, nil
}
