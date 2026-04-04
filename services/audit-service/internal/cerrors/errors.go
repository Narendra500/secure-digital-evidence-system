package cerrors

import "errors"

type CustomError struct {
	// Code is the error code returned by the database.
	Code  string
	Error error
	// HTTPCode is the HTTP status code to be returned to the client.
	HTTPCode int
}

var (
	ErrEvidenceAlreadyExists = CustomError{
		Code:     "23505",
		Error:    errors.New("evidence already exists"),
		HTTPCode: 409,
	}
	ErrEvidenceNotFound = CustomError{
		Code:     "",
		Error:    errors.New("evidence not found"),
		HTTPCode: 404,
	}
	ErrForeignKeyViolation = CustomError{
		Code:     "23503",
		Error:    errors.New("foreign key violation"),
		HTTPCode: 409,
	}
	ErrNotNullViolation = CustomError{
		Code:     "23502",
		Error:    errors.New("not null violation"),
		HTTPCode: 409,
	}
	ErrFileNotFound = CustomError{
		Code:     "",
		Error:    errors.New("file not found"),
		HTTPCode: 404,
	}
)
