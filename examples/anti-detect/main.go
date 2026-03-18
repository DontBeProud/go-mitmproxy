//go:build ignore

// anti-detect — Full anti-detection MITM proxy example
//
// Demonstrates how to combine multiple go-mitmproxy features to build a
// transparent MITM proxy that is difficult for upstream servers to detect:
//
//  1. StripProxyHeadersAddon  — remove proxy-revealing HTTP headers
//  2. RouterAddon             — gin-like routing for request/response hooks
//  3. WithServerTLSHandshake  — (placeholder) pluggable uTLS fingerprint
//  4. TLSInspectorAddon       — verify TLS handshake parameters
//
// This example uses only the standard crypto/tls handshake as a placeholder.
// For real anti-detection, inject a uTLS handshake (see examples/utls-fingerprint)
// via WithServerTLSHandshake.
//
// Run:
//
// go run main.go [-addr :9080] [-verbose]
//
// Then configure your browser/tool to use HTTP proxy at the listen address.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"strings"

	"github.com/DontBeProud/go-mitmproxy/addon"
	"github.com/DontBeProud/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr := flag.String("addr", ":9080", "proxy listen address")
	verbose := flag.Bool("verbose", false, "enable TLS handshake logging")
	flag.Parse()
	opts := &proxy.Options{
		Addr:              *addr,
		StreamLargeBodies: 1024 * 1024 * 5,
	}
	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}
	// ── 1. Strip proxy-revealing headers ───────────────────────────────────────
	// Removes Via, X-Forwarded-For, Proxy-Connection, etc.
	// Use WithExtraStripHeaders() to add custom headers.
	p.AddAddon(addon.NewStripProxyHeadersAddon(
		addon.WithExtraStripHeaders("X-Debug-Token"),
	))
	// ── 2. TLS handshake inspection (optional) ────────────────────────────────
	// Logs every outbound TLS handshake result so you can verify fingerprint.
	if *verbose {
		p.AddAddon(addon.NewTLSInspectorAddon(func(info addon.TLSHandshakeInfo) {
			fmt.Printf("[TLS] %-35s proto=%-6s ver=%s cipher=%s resumed=%v\n",
				info.ServerName,
				orDefault(info.NegotiatedProtocol, "http/1.1"),
				tlsVersionName(info.TLSVersion),
				tls.CipherSuiteName(info.CipherSuite),
				info.DidResume,
			)
		}))
	}
	// ── 3. Router-based response monitoring ───────────────────────────────────
	// Use RouterAddon for gin-like routing to inspect specific endpoints.
	r := addon.NewRouterAddon()
	// Global response middleware: detect 303 redirects to maintenance pages
	// (a common anti-proxy response pattern).
	r.OnResponse().Use(func(c *addon.FlowContext) {
		if c.Response == nil || c.Response.StatusCode != 303 {
			return
		}
		loc := c.Response.Header.Get("Location")
		if strings.Contains(loc, "maintain") || strings.Contains(loc, "blocked") {
			log.Warnf("⚠️  Anti-proxy block detected: %s → %s", c.Request.URL, loc)
		}
	})
	// Example: log all JSON API responses from a specific host
	r.OnResponse().Host("*.example.com").GET("/api/*path", func(c *addon.FlowContext) {
		if c.Response == nil {
			return
		}
		log.Infof("[API] %s /api/%s → %d (body=%d bytes)",
			c.Request.URL.Host, c.Param("path"),
			c.Response.StatusCode, len(c.Response.Body))
	})
	// Example: mock a specific endpoint
	r.OnRequest().Host("httpbin.org").GET("/get", func(c *addon.FlowContext) {
		c.Response = &proxy.Response{
			StatusCode: 200,
			Header:     map[string][]string{"Content-Type": {"application/json"}},
			Body:       []byte(`{"mocked": true, "by": "go-mitmproxy"}`),
		}
		log.Info("[Mock] Intercepted GET httpbin.org/get")
	})
	p.AddAddon(r)
	// ── 4. Standard log addon ─────────────────────────────────────────────────
	p.AddAddon(&proxy.LogAddon{})
	fmt.Printf("anti-detect proxy listening on %s (verbose=%v)\n", *addr, *verbose)
	fmt.Println("Tip: For real TLS fingerprint spoofing, use WithServerTLSHandshake with uTLS.")
	fmt.Println("     See examples/utls-fingerprint for details.")
	log.Fatal(p.Start())
}
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
