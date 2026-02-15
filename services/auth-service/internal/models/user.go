package models

import (
	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID       string `json:"user_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type UserPublic struct {
	ID       string
	Email    string
	Username string
}

type Claims struct {
	UserID   string `json:"id"`
	UserName string `json:"name"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}
