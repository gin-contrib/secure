package secure

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type (
	// Secure is a middleware that helps setup a few basic security features. A single secure.Options struct can be
	// provided to configure which features should be enabled, and the ability to override a few of the default values.
	policy struct {
		// Customize Secure with an Options struct.
		config       Config
		fixedHeaders []header
	}

	header struct {
		key   string
		value []string
	}
)

// Constructs a new Policy instance with supplied options.
func newPolicy(config Config) *policy {
	policy := &policy{}
	policy.loadConfig(config)
	return policy
}

func (p *policy) loadConfig(config Config) {
	p.config = config
	p.fixedHeaders = make([]header, 0, 5)

	// Frame Options header.
	if len(config.CustomFrameOptionsValue) > 0 {
		p.addHeader("X-Frame-Options", config.CustomFrameOptionsValue)
	} else if config.FrameDeny {
		p.addHeader("X-Frame-Options", "DENY")
	}

	// Content Type Options header.
	if config.ContentTypeNosniff {
		p.addHeader("X-Content-Type-Options", "nosniff")
	}

	// XSS Protection header.
	if config.BrowserXssFilter {
		p.addHeader("X-Xss-Protection", "1; mode=block")
	}

	// Content Security Policy header.
	if len(config.ContentSecurityPolicy) > 0 {
		p.addHeader("Content-Security-Policy", config.ContentSecurityPolicy)
	}

	if len(config.ReferrerPolicy) > 0 {
		p.addHeader("Referrer-Policy", config.ReferrerPolicy)
	}

	// Strict Transport Security header.
	if config.STSSeconds != 0 {
		stsSub := ""
		if config.STSIncludeSubdomains {
			stsSub = "; includeSubdomains"
		}

		// TODO
		// "max-age=%d%s" refactor
		p.addHeader(
			"Strict-Transport-Security",
			fmt.Sprintf("max-age=%d%s", config.STSSeconds, stsSub))
	}

	// X-Download-Options header.
	if config.IENoOpen {
		p.addHeader("X-Download-Options", "noopen")
	}

	// FeaturePolicy header.
	if len(config.FeaturePolicy) > 0 {
		p.addHeader("Feature-Policy", config.FeaturePolicy)
	}
}

func (p *policy) addHeader(key string, value string) {
	p.fixedHeaders = append(p.fixedHeaders, header{
		key:   key,
		value: []string{value},
	})
}

func (p *policy) apply(res http.ResponseWriter, req *http.Request) bool {
	if !p.config.IsDevelopment {
		p.writeSecureHeaders(res, req)

		if !p.checkAllowHosts(res, req) {
			return false
		}
		if !p.checkSSL(res, req) {
			return false
		}
	}
	return true
}

func (p *policy) writeSecureHeaders(res http.ResponseWriter, req *http.Request) {
	header := res.Header()
	for _, pair := range p.fixedHeaders {
		header[pair.key] = pair.value
	}
}

func (p *policy) checkAllowHosts(res http.ResponseWriter, req *http.Request) bool {
	if len(p.config.AllowedHosts) == 0 {
		return true
	}

	host := req.Host
	if len(host) == 0 {
		host = req.URL.Host
	}

	for _, allowedHost := range p.config.AllowedHosts {
		if strings.EqualFold(allowedHost, host) {
			return true
		}
	}

	if p.config.BadHostHandler != nil {
		p.config.BadHostHandler(res, req)
	} else {
		res.WriteHeader(http.StatusForbidden)
	}

	return false
}

// checks if a host (possibly with trailing port) is an IPV4 address
func isIPV4(host string) bool {
	if index := strings.IndexByte(host, ':'); index != -1 {
		host = host[:index]
	}
	return net.ParseIP(host) != nil
}

func (p *policy) isSSLRequest(req *http.Request) bool {
	if strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil {
		return true
	}

	for h, v := range p.config.SSLProxyHeaders {
		hv, ok := req.Header[h]

		if !ok {
			continue
		}

		if strings.EqualFold(hv[0], v) {
			return true
		}
	}

	if p.config.DontRedirectIPV4Hostnames && isIPV4(req.Host) {
		return true
	}

	return false
}

func (p *policy) checkSSL(res http.ResponseWriter, req *http.Request) bool {
	if !p.config.SSLRedirect {
		return true
	}

	isSSLRequest := p.isSSLRequest(req)
	if isSSLRequest {
		return true
	}

	// TODO
	// req.Host vs req.URL.Host
	url := req.URL
	url.Scheme = "https"
	url.Host = req.Host

	if len(p.config.SSLHost) > 0 {
		url.Host = p.config.SSLHost
	}

	status := http.StatusMovedPermanently
	if p.config.SSLTemporaryRedirect {
		status = http.StatusTemporaryRedirect
	}

	http.Redirect(res, req, url.String(), status)
	return false
}
