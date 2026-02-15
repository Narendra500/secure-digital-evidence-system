package auth

import (
	"auth-service-go/internal/models"
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var privateKey *rsa.PrivateKey

// Sets the private key to use for generating access tokens.
// Takes pointer to a rsa privatekey.
func SetPrivateKey(key *rsa.PrivateKey) {
	privateKey = key
}

// Hash the given password using bcrypt.
// Returns a tuple of password hash and error if any.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Match the plaintext password with a password hash.
// Returns true if the plaintext password's hash matchs the hash given.
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Generate access token with the given claims.
func GenerateToken(userID string, userName string, email string) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key not initialized")
	}

	accessClaims := &models.Claims{
		UserID:   userID,
		UserName: userName,
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Minute)),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims).SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return accessToken, err
}
