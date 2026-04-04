package repository

import (
	"audit-service/internal/cerrors"
	"audit-service/internal/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type auditRepo struct {
	store *store.Storage
}

func NewAuditRepo(store *store.Storage) AuditRepo {
	return &auditRepo{store: store}
}

// Returns a querier for the database.
func (a *auditRepo) q(ctx context.Context) store.PgxQuerier {
	tx := store.ExtractTx(ctx)
	if tx != nil {
		return tx // Use the transaction passed down via the context.
	}
	return a.store.Pool // No transaction passed, use the database.
}

func hashRowContents(row store.AuditLog, prevRowHash string) string {
	concatenatedRow := strconv.Itoa(int(row.UserID)) + strconv.Itoa(int(row.CaseID)) + strconv.Itoa(int(row.EvidenceId)) + strconv.Itoa(int(row.ActionType)) + row.ServiceName + row.IPAddress + prevRowHash

	hash := sha256.Sum256([]byte(concatenatedRow))
	hashString := hex.EncodeToString(hash[:])
	return hashString
}

func (a auditRepo) InsertAuditLog(ctx context.Context, auditLog store.AuditLog) error {
	var prevRowHash string
	// Query to get the previous hash for the same evidence.
	getPrevHashQuery := `
			SELECT current_hash
			FROM integrity_schema.audit_logs
			WHERE evidence_id = @evidenceID
			ORDER BY created_at DESC LIMIT 1;
			FOR UPDATE
		`
	prevHashArgs := pgx.NamedArgs{"evidenceID": auditLog.EvidenceId}

	// Get the previous hash for the same evidence from the database. `FOR UPDATE` ensures that the row is locked for the duration of the transaction.
	row := a.q(ctx).QueryRow(ctx, getPrevHashQuery, prevHashArgs)

	if err := row.Scan(&prevRowHash); err != nil {
		// no previous row found
		prevRowHash = ""
	}

	// Calculate the new hash for the row.
	newHash := hashRowContents(auditLog, prevRowHash)

	// Query to the new row into the database.
	query := `
			INSERT INTO integrity_schema.audit_logs(user_id, case_id, evidence_id, action_type, service_name, ip_address, previous_hash, current_hash)
			VALUES(@userID, @caseID, @evidenceID, @actionType, @serviceName, @ipAdress, @previousHash, @currentHash)
		`
	args := pgx.NamedArgs{
		"userID":       auditLog.UserID,
		"caseID":       auditLog.CaseID,
		"evidenceID":   auditLog.EvidenceId,
		"actionType":   auditLog.ActionType,
		"serviceName":  auditLog.ServiceName,
		"ipAdress":     auditLog.IPAddress,
		"previousHash": prevRowHash,
		"currentHash":  newHash,
	}

	// Execute the query.
	_, err := a.q(ctx).Exec(ctx, query, args)
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
		log.Printf("error: failed to insert audit log, %v", err)
		return fmt.Errorf("error: failed to insert audit log, %w", err)
	}

	return nil
}
