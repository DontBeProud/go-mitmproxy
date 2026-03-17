// Demonstrates WithServerTlsConfig, which lets callers control the tls.Config
// used when the proxy dials upstream (target) servers.
//
// Background: without this, Go's crypto/tls uses its own defaults, producing a
// JA3 fingerprint that is easily recognised as a Go HTTP client rather than a
// real browser. By mirroring the original client's ClientHelloInfo the proxy
// forwards cipher suites, supported versions, ALPN protocols, and elliptic
// curves that match the browser's own TLS fingerprint.
//
// Usage:
//
//	go run . [-addr :9080] [-ssl-insecure] [-verbose]
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"strings"

	"github.com/DontBeProud/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr := flag.String("addr", ":9080", "proxy listen address")
	insecure := flag.Bool("ssl-insecure", false, "skip upstream TLS verification")
	verbose := flag.Bool("verbose", false, "log per-connection TLS fingerprint details")
	flag.Parse()

	opts := &proxy.Options{
		Addr:              *addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       *insecure,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	// WithServerTlsConfig injects a factory function that is called once per
	// upstream TLS handshake. hello carries the parameters from the original
	// client's ClientHello message, which we mirror so the proxy's own JA3
	// fingerprint matches the real browser instead of the Go TLS defaults.
	p.WithServerTlsConfig(buildServerTlsConfig(opts.SslInsecure, *verbose))

	p.AddAddon(&proxy.LogAddon{})

	fmt.Printf("proxy listening on %s (ssl-insecure=%v, verbose=%v)\n", *addr, *insecure, *verbose)
	log.Fatal(p.Start())
}

// buildServerTlsConfig returns a ServerTlsConfigFunc that mirrors the original
// client's ClientHelloInfo when connecting to upstream servers.
//
// JA3 hash inputs and how each is handled:
//
//	TLS version     → derived from hello.SupportedVersions (min/max)
//	Cipher suites   → hello.CipherSuites
//	Extensions      → controlled internally by crypto/tls; not overridable here
//	Elliptic curves → hello.SupportedCurves  (see note below)
//	Point formats   → controlled internally by crypto/tls
//
// Note on CurvePreferences: the built-in default intentionally leaves
// CurvePreferences unset because certain server/curve combinations can cause
// handshake failures with the standard crypto/tls implementation. It is
// enabled here to achieve a more complete fingerprint match; disable it if you
// encounter handshake errors against specific targets.
func buildServerTlsConfig(insecure, verbose bool) func(*tls.ClientHelloInfo) *tls.Config {
	return func(hello *tls.ClientHelloInfo) *tls.Config {
		cfg := &tls.Config{
			InsecureSkipVerify: insecure,
			ServerName:         hello.ServerName,
			CipherSuites:       hello.CipherSuites,
			NextProtos:         hello.SupportedProtos,
			CurvePreferences:   hello.SupportedCurves,
		}

		if len(hello.SupportedVersions) > 0 {
			minVer, maxVer := hello.SupportedVersions[0], hello.SupportedVersions[0]
			for _, v := range hello.SupportedVersions {
				if v < minVer {
					minVer = v
				}
				if v > maxVer {
					maxVer = v
				}
			}
			cfg.MinVersion = minVer
			cfg.MaxVersion = maxVer
		}

		if verbose {
			log.Infof("upstream TLS for %-30s ciphers=%s protos=%s",
				hello.ServerName,
				formatCiphers(cfg.CipherSuites),
				strings.Join(cfg.NextProtos, ","),
			)
		}

		return cfg
	}
}

func formatCiphers(ids []uint16) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = tls.CipherSuiteName(id)
		if parts[i] == fmt.Sprintf("0x%04X", id) {
			// fallback for suites not in the standard library's name table
			parts[i] = fmt.Sprintf("0x%04x", id)
		}
	}
	return "[" + strings.Join(parts, " ") + "]"
}
