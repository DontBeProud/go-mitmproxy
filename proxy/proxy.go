package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"

	"github.com/DontBeProud/go-mitmproxy/cert"
	"github.com/DontBeProud/go-mitmproxy/internal/helper"
	log "github.com/sirupsen/logrus"
)

// ServerTLSHandshakeFunc is the signature for a pluggable outbound TLS handshake.
//
//   - rawConn     – the already-established TCP connection to the upstream server
//   - serverName  – SNI from the browser's ClientHello
//   - clientHello – the full ClientHello received from the browser (nil in lazy mode)
//
// The function must complete the TLS handshake and return:
//   - a net.Conn wrapping rawConn with TLS applied
//   - the resulting *tls.ConnectionState (needed for ALPN negotiation and addons)
//   - any error
//
// This keeps the proxy library free of any specific TLS fingerprinting dependency.
// Supply an implementation via Options.ServerTLSHandshake or WithServerTLSHandshake.
type ServerTLSHandshakeFunc func(
	ctx context.Context,
	rawConn net.Conn,
	serverName string,
	clientHello *tls.ClientHelloInfo,
) (net.Conn, *tls.ConnectionState, error)

type Options struct {
	Debug             int
	Addr              string
	StreamLargeBodies int64 // 当请求或响应体大于此字节时，转为 stream 模式
	SslInsecure       bool
	CaRootPath        string
	NewCaFunc         func() (cert.CA, error) // 创建 Ca 的函数
	Upstream          string
	LogFilePath       string // Path to write logs to file

	// ServerTLSHandshake, when non-nil, replaces the default crypto/tls outbound
	// TLS handshake with a caller-supplied implementation.
	// Typical use: inject a uTLS (bogdanfinn/utls or refraction-networking/utls)
	// handshake to mimic a specific browser's TLS/JA3 fingerprint.
	// Can also be set after NewProxy via WithServerTLSHandshake.
	ServerTLSHandshake ServerTLSHandshakeFunc

	// ServerH2ClientFactory, when non-nil, replaces the default http2.Transport
	// used for upstream HTTP/2 connections. The factory receives the already-established
	// TLS connection (from ServerTLSHandshake or default handshake) and must return
	// an *http.Client whose Transport speaks HTTP/2 over that connection.
	//
	// Typical use: inject a bogdanfinn/fhttp based transport to mimic Chrome's
	// HTTP/2 SETTINGS / WINDOW_UPDATE / PRIORITY fingerprint.
	// Can also be set after NewProxy via WithServerH2ClientFactory.
	ServerH2ClientFactory func(tlsConn net.Conn) *http.Client
}

type Proxy struct {
	Opts    *Options
	Version string
	Addons  []Addon

	entry               *entry
	attacker            *attacker
	webSocketHandler    *webSocketHandler
	shouldIntercept     func(req *http.Request) bool
	upstreamProxy       func(req *http.Request) (*url.URL, error)
	authProxy           func(res http.ResponseWriter, req *http.Request) (bool, error)
	serverTlsConfigFunc func(*tls.ClientHelloInfo) *tls.Config
}

// proxy.server req context key
var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:    opts,
		Version: "1.8.10",
		Addons:  make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	proxy.webSocketHandler = newWebSocketHandler(proxy)

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			log.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) Shutdown(ctx context.Context) error {
	return proxy.entry.shutdown(ctx)
}

// WithServerTLSHandshake sets a pluggable outbound TLS handshake function and
// returns the Proxy for chaining.  When set, the proxy calls fn instead of the
// built-in crypto/tls handshake for every HTTPS upstream connection, allowing
// callers to substitute uTLS or any other TLS implementation without this library
// importing it.
//
// Example (bogdanfinn/utls, Chrome 146 fingerprint):
//
//	proxy.WithServerTLSHandshake(func(ctx context.Context, raw net.Conn, sni string, _ *tls.ClientHelloInfo) (net.Conn, *tls.ConnectionState, error) {
//	    uc := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: false}, utls.HelloChrome_146)
//	    if err := uc.HandshakeContext(ctx); err != nil { return nil, nil, err }
//	    st := uc.ConnectionState()
//	    return uc, &st, nil
//	})
func (proxy *Proxy) WithServerTLSHandshake(fn ServerTLSHandshakeFunc) *Proxy {
	proxy.Opts.ServerTLSHandshake = fn
	return proxy
}

// WithServerH2ClientFactory sets a pluggable HTTP/2 client factory and returns
// the Proxy for chaining.  When set, the proxy calls fn instead of using the
// built-in http2.Transport for every upstream HTTP/2 connection.
//
// The factory receives the already-established TLS connection (after the TLS
// handshake is complete) and must return an *http.Client whose Transport speaks
// HTTP/2 over that connection.
//
// Typical use: inject a bogdanfinn/fhttp based transport to mimic Chrome's
// HTTP/2 SETTINGS / WINDOW_UPDATE / PRIORITY fingerprint.
func (proxy *Proxy) WithServerH2ClientFactory(fn func(tlsConn net.Conn) *http.Client) *Proxy {
	proxy.Opts.ServerH2ClientFactory = fn
	return proxy
}

// WithServerTlsConfig sets a factory that returns the *tls.Config used when
// connecting to upstream servers via the built-in crypto/tls path.
// Deprecated: prefer WithServerTLSHandshake for full control over the handshake.
// Returns the Proxy for chaining.
func (proxy *Proxy) WithServerTlsConfig(fn func(*tls.ClientHelloInfo) *tls.Config) *Proxy {
	proxy.serverTlsConfigFunc = fn
	return proxy
}

func (proxy *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	proxy.shouldIntercept = rule
}

func (proxy *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	proxy.upstreamProxy = fn
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyUrl(req)
	}
}

func (proxy *Proxy) getUpstreamProxyUrl(req *http.Request) (*url.URL, error) {
	if proxy.upstreamProxy != nil {
		return proxy.upstreamProxy(req)
	}
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyUrl, err := proxy.getUpstreamProxyUrl(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := helper.CanonicalAddr(req.URL)
	if proxyUrl != nil {
		conn, err = helper.GetProxyConn(ctx, proxyUrl, address, proxy.Opts.SslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}

func (proxy *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	proxy.authProxy = fn
}

func (proxy *Proxy) GetCertificate() x509.Certificate {
	return *proxy.attacker.ca.GetRootCA()
}

func (proxy *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return proxy.attacker.ca.GetCert(commonName)
}
