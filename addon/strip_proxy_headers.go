package addon

import "github.com/DontBeProud/go-mitmproxy/proxy"

// StripProxyHeadersAddon removes HTTP headers that reveal the presence of a
// proxy (Via, X-Forwarded-For, Proxy-Connection, etc.) from every outbound
// request.  This is a common requirement when building MITM proxies that must
// appear transparent to the upstream server.
//
// By default, the addon strips a well-known set of headers.  Callers can
// customise this set via WithExtraStripHeaders (add more) or
// WithStripHeaders (replace entirely).
//
// Example:
//
// p.AddAddon(addon.NewStripProxyHeadersAddon())
//
// Or with extra custom headers:
//
// p.AddAddon(
//
//	addon.NewStripProxyHeadersAddon(
//	    addon.WithExtraStripHeaders("X-Custom-Debug", "X-Internal-ID"),
//	),
//
// )
type StripProxyHeadersAddon struct {
	proxy.BaseAddon
	headers []string
}

// StripProxyHeadersOption configures a StripProxyHeadersAddon.
type StripProxyHeadersOption func(*StripProxyHeadersAddon)

// defaultStripHeaders is the default set of headers removed by the addon.
// These are the most common headers that expose the use of a proxy.
var defaultStripHeaders = []string{
	"Via",
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-IP",
	"Proxy-Connection",
	"X-Proxy-ID",
}

// WithStripHeaders replaces the entire default header list with the given set.
func WithStripHeaders(headers ...string) StripProxyHeadersOption {
	return func(a *StripProxyHeadersAddon) {
		a.headers = make([]string, len(headers))
		copy(a.headers, headers)
	}
}

// WithExtraStripHeaders appends additional header names to the default list.
func WithExtraStripHeaders(headers ...string) StripProxyHeadersOption {
	return func(a *StripProxyHeadersAddon) {
		a.headers = append(a.headers, headers...)
	}
}

// NewStripProxyHeadersAddon creates a new StripProxyHeadersAddon.
// Without options it strips the default set of proxy-revealing headers.
func NewStripProxyHeadersAddon(opts ...StripProxyHeadersOption) *StripProxyHeadersAddon {
	a := &StripProxyHeadersAddon{
		headers: make([]string, len(defaultStripHeaders)),
	}
	copy(a.headers, defaultStripHeaders)
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Requestheaders strips configured headers from every request before it is
// forwarded to the upstream server.
func (a *StripProxyHeadersAddon) Requestheaders(f *proxy.Flow) {
	for _, h := range a.headers {
		f.Request.Header.Del(h)
	}
}
