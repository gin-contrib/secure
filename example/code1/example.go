package main

import (
	"log"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

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

	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	// Listen and Server in 0.0.0.0:8080
	if err := router.Run(); err != nil {
		log.Fatal(err)
	}
}
