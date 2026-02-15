package handlerauth

import (
	"auth-service-go/internal/auth"
	"auth-service-go/internal/models"
	"auth-service-go/internal/store"
	"encoding/json"

	"net/http"
)

type AuthHandler struct {
	Store *store.Storage
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var creds models.User

	// Get the user details from user credentials from request body.
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Hash the user password.
	hashedPassword, _ := auth.HashPassword(creds.Password)
	creds.Password = hashedPassword

	// insert new user into database.
	if err := h.Store.CreateUser(&creds); err != nil {
		http.Error(w, "Could not create user", http.StatusInternalServerError)
		return
	}

	// generate the access token. Valid for 1 hour.
	accToken, err := auth.GenerateToken(creds.ID, creds.Name, creds.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"user_id": creds.ID, "user_name": creds.Name, "access_token": accToken})
	w.WriteHeader(http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var creds models.User

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// get user with the email from the database.
	user, err := h.Store.GetUserByEmail(creds.Email)
	// return error if user doesn't already exists or password doesn't match the password.
	if err != nil || !auth.CheckPassword(creds.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// generate the access token. Valid for 1 hour.
	accToken, err := auth.GenerateToken(user.ID, user.Name, user.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"user_name": user.Name, "user_id": user.ID, "access_token": accToken})
}
