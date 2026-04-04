package store

import (
	"audit-service/internal/config"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	Pool *pgxpool.Pool
}

func NewStorage(config *config.EnvDBConfig, setLimits bool, ctx context.Context) (*Storage, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.GetHost(),
		config.GetPort(),
		config.GetUsername(),
		config.GetPassword(),
		config.GetDatabase())
	const tries = 5
	const timeout = 2

	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("error: failed to parse config, %w", err)
	}

	if setLimits {
		maxConns := config.GetMaxConns()
		minConns := config.GetMinConns()
		maxConnIdleTime := config.GetMaxConnIdleTime()
		log.Printf("Setting connection limits, maxConns: %d, minConns: %d, maxConnIdleTime: %s", maxConns, minConns, maxConnIdleTime)

		poolConfig.MaxConns = maxConns
		poolConfig.MinConns = minConns
		poolConfig.MaxConnIdleTime = maxConnIdleTime
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("error: failed to create pool, %w", err)
	}

	var pingErr error
	// Start loop to keep try to connect to db with a timeout.
	for i := range tries {
		pingErr = pool.Ping(ctx)
		// db connection good.
		if pingErr == nil {
			return &Storage{pool}, nil
		}

		fmt.Printf("Database not ready... restarting in %ds (%d/%d): %v\n", timeout, i+1, tries, pingErr)
		time.Sleep(timeout * time.Second)
	}

	// Clean up the pool if we completely failed to connect.
	pool.Close()
	return nil, fmt.Errorf("could not connect to database after %d retires: %v", tries, pingErr)
}

func (t *Storage) Close() {
	t.Pool.Close()
}

func (t *Storage) HealthCheck() error {
	ctx := context.Background()
	err := t.Pool.Ping(ctx)
	if err != nil {
		return fmt.Errorf("error: failed to ping db, %w", err)
	}
	return nil
}

// PgxQuerier defines the standard database operations.
// Both *pgxpool.Pool and pgx.Tx satisfy this interface.
type PgxQuerier interface {
	Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, query string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) pgx.Row
}

// txKey is a custom type to avoid context key collisions.
type txKey struct{}

// InjectTx places a transaction into the context.
func InjectTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// ExtractTx retrieves a transaction from the context if one exists.
func ExtractTx(ctx context.Context) pgx.Tx {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return nil
}

func (t *Storage) WithinTransactionReadCommitted(context context.Context, fn func(txCtx context.Context) error) error {
	tx, err := t.Pool.BeginTx(context, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, // Isolation of the row is ensured through explicit locking via FOR UPDATE instead of serializable.
	})
	if err != nil {
		return fmt.Errorf("error: failed to begin tx, %w", err)
	}

	defer tx.Rollback(context)

	// Inject the transaction into a new context.
	txCtx := InjectTx(context, tx)

	// Execute the callback function with new context.
	err = fn(txCtx)
	if err != nil {
		return fmt.Errorf("error: failed to execute tx, %w", err)
	}

	return tx.Commit(context)
}
