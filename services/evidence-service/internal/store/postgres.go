package store



import (

"github.com/jmoiron/sqlx"

_ "github.com/jackc/pgx/v5/stdlib"

)
type Storage struct {

DB *sqlx.DB

}

func NewStorage(connStr string) (*Storage, error) {

db, err := sqlx.Connect("pgx", connStr)

if err != nil {

return nil, err

}

return &Storage{DB: db}, nil

}