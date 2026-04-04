package models

import "time"

type Evidence struct {
	ID          int64     `db:"id"           json:"id"`
	PublicID    string    `db:"public_id"    json:"public_id"`
	CaseID      string    `db:"case_id"      json:"case_id"`
	FileName    string    `db:"file_name"    json:"file_name"`
	FileSize    int64     `db:"file_size"    json:"file_size"`
	StoragePath string    `db:"storage_path" json:"storage_path"`
	CurrentHash string    `db:"current_hash" json:"current_hash"`
	UploadedBy  string    `db:"uploaded_by"  json:"uploaded_by"`
	UploadedAt  time.Time `db:"uploaded_at"  json:"uploaded_at"`
}