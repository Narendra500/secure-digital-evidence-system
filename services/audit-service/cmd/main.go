package main

import (
	"audit-service/internal/config"
	"audit-service/internal/handler"
	"audit-service/internal/repository"
	"audit-service/internal/service"
	"audit-service/internal/store"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	// Initialize the database configuration.
	config := config.NewEnvDBConfig(5, 5, time.Duration(30*time.Minute))

	runMigrations(config)

	// Initial context acting as top level context for incoming requests.
	ctx := context.Background()

	// Initialize the storage layer.
	store, err := store.NewStorage(config, true, ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	// Initialize the repositories.
	evidenceRepo := repository.NewEvidenceRepo(store)
	custodyRepo := repository.NewCustodyRepo(store)
	auditRepo := repository.NewAuditRepo(store)

	// Initialize the services.
	registrationService := service.NewEvidenceRegistrationWorkflow(store, evidenceRepo, custodyRepo, auditRepo)

	// Initialze the handler.
	handler := handler.NewHandler(registrationService)

	router := gin.Default()

	// Routes.
	router.POST("/api/v1/evidence/register", handler.RegisterEvidence)
	router.GET("/api/v1/evidence/:id/verify", handler.VerifyEvidence)

	log.Printf("Service running on : %s\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", port), router))
}

// Run the latest db migrations.
func runMigrations(config *config.EnvDBConfig) error {
	m, err := migrate.New(
		"file://./migrations",
		fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			config.GetUsername(),
			config.GetPassword(),
			config.GetHost(),
			config.GetPort(),
			config.GetDatabase(),
		),
	)
	if err != nil {
		return fmt.Errorf("Migration failed to initialize %v", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("Failed to apply migrations: %v", err)
	}

	log.Println("Migrations successfully applied")

	return nil
}
