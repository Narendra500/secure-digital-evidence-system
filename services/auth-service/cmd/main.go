package main

import (
	"auth-service-go/internal/auth"
	"auth-service-go/internal/handler"
	"auth-service-go/internal/store"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()
	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	privBytes, err := os.ReadFile("private.pem")
	if err != nil {
		log.Fatal(err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		log.Fatal(err)
	}

	auth.SetPrivateKey(privateKey)

	connStr := os.Getenv("DB_CONN_STR")
	if connStr == "" {
		log.Fatal("No db connStr provided")
	}

	db, err := store.NewStorage(connStr)
	if err != nil {
		log.Fatal(err)
	}

	h := &handlerauth.AuthHandler{Store: db}
	router := mux.NewRouter()

	router.HandleFunc("/api/v1/auth/register", h.Register).Methods("POST")
	router.HandleFunc("/api/v1/auth/login", h.Login).Methods("POST")

	log.Println("Service running on :3001")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%s", port), router))
}
