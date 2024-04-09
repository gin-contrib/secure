package main

import (
	"log"
	"net/http"

	"github.com/gin-contrib/secure"
	"github.com/go-chi/chi/v5"
)

func main() {
	router := chi.NewRouter()

	router.Use(secure.New(secure.Config{
		AllowedHosts:          []string{"example.com", "ssl.example.com"},
		SSLRedirect:           true,
		SSLHost:               "ssl.example.com",
		STSSeconds:            315360000,
		STSIncludeSubdomains:  true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
		IENoOpen:              true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
	}))

	router.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})

	// Listen and Server in 0.0.0.0:8080
	server := &http.Server{Handler: router}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
