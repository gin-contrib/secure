package main

import (
	"log"
	"net/http"

	"github.com/gin-contrib/secure"
	"github.com/go-chi/chi/v5"
)

func main() {
	router := chi.NewRouter()

	securityConfig := secure.DefaultConfig()
	securityConfig.AllowedHosts = []string{"example.com", "ssl.example.com"}
	securityConfig.SSLHost = "ssl.example.com"
	router.Use(secure.New(securityConfig))

	router.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	server := &http.Server{Handler: router}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
