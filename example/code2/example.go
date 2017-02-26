package main

import (
	"github.com/gin-contrib/secure"
	"gopkg.in/gin-gonic/gin.v1"
)

func main() {
	router := gin.Default()

	securityConfig := secure.DefaultConfig()
	securityConfig.AllowedHosts = []string{"example.com", "ssl.example.com"}
	securityConfig.SSLHost = "ssl.example.com"
	router.Use(secure.New(securityConfig))

	router.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	router.Run()
}
