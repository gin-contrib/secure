package secure

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	testResponse = "bar"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newServer(options Config) *gin.Engine {
	router := gin.New()
	router.Use(New(options))
	router.GET("/foo", func(c *gin.Context) {
		c.String(200, testResponse)
	})
	return router
}

func performRequest(router *gin.Engine, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", path, nil)
	router.ServeHTTP(w, req)
	return w
}

func TestNoConfig(t *testing.T) {
	router := newServer(Config{
	// Intentionally left blank.
	})

	w := performRequest(router, "http://example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestNoAllowHosts(t *testing.T) {
	router := newServer(Config{
		AllowedHosts: []string{},
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestGoodSingleAllowHosts(t *testing.T) {
	router := newServer(Config{
		AllowedHosts: []string{"www.example.com"},
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestBadSingleAllowHosts(t *testing.T) {
	router := newServer(Config{
		AllowedHosts: []string{"sub.example.com"},
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusForbidden)
}

func TestGoodMultipleAllowHosts(t *testing.T) {
	router := newServer(Config{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	w := performRequest(router, "http://sub.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestBadMultipleAllowHosts(t *testing.T) {
	router := newServer(Config{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	w := performRequest(router, "http://www3.example.com/foo")

	assert.Equal(t, w.Code, http.StatusForbidden)
}
func TestAllowHostsInDevMode(t *testing.T) {
	router := newServer(Config{
		AllowedHosts:  []string{"www.example.com", "sub.example.com"},
		IsDevelopment: true,
	})

	w := performRequest(router, "http://www3.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
}

func TestBadHostHandler(t *testing.T) {

	badHandler := func(c *gin.Context) {
		http.Error(c.Writer, "BadHost", http.StatusInternalServerError)
	}

	router := newServer(Config{
		AllowedHosts:   []string{"www.example.com", "sub.example.com"},
		BadHostHandler: badHandler,
	})

	w := performRequest(router, "http://www3.example.com/foo")

	assert.Equal(t, w.Code, http.StatusInternalServerError)
	assert.Equal(t, w.Body.String(), "BadHost\n")
}

func TestSSL(t *testing.T) {
	router := newServer(Config{
		SSLRedirect: true,
	})

	w := performRequest(router, "https://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestSSLInDevMode(t *testing.T) {
	router := newServer(Config{
		SSLRedirect:   true,
		IsDevelopment: true,
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Body.String(), "bar")
}

func TestBasicSSL(t *testing.T) {
	router := newServer(Config{
		SSLRedirect: true,
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusMovedPermanently)
	assert.Equal(t, w.Header().Get("Location"), "https://www.example.com/foo")
}

func TestBasicSSLWithHost(t *testing.T) {
	router := newServer(Config{
		SSLRedirect: true,
		SSLHost:     "secure.example.com",
	})

	w := performRequest(router, "http://www.example.com/foo")

	assert.Equal(t, w.Code, http.StatusMovedPermanently)
	assert.Equal(t, w.Header().Get("Location"), "https://secure.example.com/foo")
}

func TestBadProxySSL(t *testing.T) {
	router := newServer(Config{
		SSLRedirect: true,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	router.ServeHTTP(w, req)

	assert.Equal(t, w.Code, http.StatusMovedPermanently)
	assert.Equal(t, w.Header().Get("Location"), "https://www.example.com/foo")
}

func TestStsHeader(t *testing.T) {
	router := newServer(Config{
		STSSeconds: 315360000,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Strict-Transport-Security"), "max-age=315360000")
}

func TestStsHeaderInDevMode(t *testing.T) {
	router := newServer(Config{
		STSSeconds:    315360000,
		IsDevelopment: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithSubdomain(t *testing.T) {
	router := newServer(Config{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubdomains")
}

func TestFrameDeny(t *testing.T) {
	router := newServer(Config{
		FrameDeny: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-Frame-Options"), "DENY")
}

func TestCustomFrameValue(t *testing.T) {
	router := newServer(Config{
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func TestCustomFrameValueWithDeny(t *testing.T) {
	router := newServer(Config{
		FrameDeny:               true,
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func TestContentNosniff(t *testing.T) {
	router := newServer(Config{
		ContentTypeNosniff: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-Content-Type-Options"), "nosniff")
}

func TestXSSProtection(t *testing.T) {
	router := newServer(Config{
		BrowserXssFilter: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-XSS-Protection"), "1; mode=block")
}

func TestCsp(t *testing.T) {
	router := newServer(Config{
		ContentSecurityPolicy: "default-src 'self'",
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

func TestInlineSecure(t *testing.T) {
	router := newServer(Config{
		FrameDeny: true,
	})

	w := performRequest(router, "/foo")

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("X-Frame-Options"), "DENY")
}
