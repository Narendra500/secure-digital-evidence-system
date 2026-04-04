package store

import (
	"auth-service-go/internal/models"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

type Storage struct {
	DB *sqlx.DB
}

// Create new storage handler.
// Takes connection string to the database.
// Returns pointer to the new storage handler created.
func NewStorage(connStr string) (*Storage, error) {
	const tries = 5
	const timeout = 2

	// prepare the driver (Lazy, doesn't actaully connect)
	db, err := sqlx.Open("pgx", connStr)
	if err != nil {
		return nil, err
	}

	for i := range tries {
		err = db.Ping()
		if err == nil {
			return &Storage{DB: db}, nil
		}
		fmt.Printf("Database not ready... retrying in %ds (%d/%d)\n", timeout, i+1, tries)
		time.Sleep(timeout * time.Second)
	}

	return nil, fmt.Errorf("could not connect to database after retries: %v", err)
}

func (s *Storage) CreateUser(user *models.User) error {
	query := `INSERT INTO users (email, name, password_hash) 
			  VALUES ($1, $2, $3)
			  RETURNING public_id, name, email`

	return s.DB.QueryRow(query, user.Email, user.Name, user.Password).Scan(&user.ID, &user.Name, &user.Email)
}

func (s *Storage) GetUserRoleIDByName(roleName string) (int, error) {
	var roleID int
	query := `SELECT id FROM roles WHERE name = $1`
	err := s.DB.QueryRow(query, roleName).Scan(&roleID)

	if err != nil {
		return 0, err
	}

	return roleID, nil
}

func (s *Storage) GetUserRoleByID(roleID int) (string, error) {
	var roleName string
	query := `SELECT name FROM roles WHERE id = $1`
	err := s.DB.QueryRow(query, roleID).Scan(&roleName)

	if err != nil {
		return "", err
	}

	return roleName, nil
}

func (s *Storage) GetUserByPublicID(ID string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT public_id as id, name, email, password_hash
		FROM users  
		WHERE public_id = $1
	`
	err := s.DB.QueryRow(query, ID).Scan(&user.ID, &user.Name, &user.Email, &user.Password)

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Storage) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT public_id as id, name, email, password_hash
		FROM users  
		WHERE email = $1
	`
	err := s.DB.QueryRow(query, email).Scan(&user.ID, &user.Name, &user.Email, &user.Password)

	if err != nil {
		return nil, err
	}

	return user, nil
}
