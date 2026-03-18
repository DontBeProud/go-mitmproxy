package addon

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/DontBeProud/go-mitmproxy/proxy"
)

func newStripTestFlow(headers map[string]string) *proxy.Flow {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	return &proxy.Flow{
		Request: &proxy.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "https", Host: "example.com", Path: "/"},
			Header: h,
		},
	}
}
func TestStripProxyHeadersDefault(t *testing.T) {
	a := NewStripProxyHeadersAddon()
	f := newStripTestFlow(map[string]string{
		"Via":             "1.1 proxy",
		"X-Forwarded-For": "10.0.0.1",
		"Accept":          "text/html",
		"User-Agent":      "Mozilla/5.0",
	})
	a.Requestheaders(f)
	if f.Request.Header.Get("Via") != "" {
		t.Error("Via should be stripped")
	}
	if f.Request.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For should be stripped")
	}
	if f.Request.Header.Get("Accept") != "text/html" {
		t.Error("Accept should be preserved")
	}
	if f.Request.Header.Get("User-Agent") != "Mozilla/5.0" {
		t.Error("User-Agent should be preserved")
	}
}
func TestStripProxyHeadersWithExtra(t *testing.T) {
	a := NewStripProxyHeadersAddon(WithExtraStripHeaders("X-Debug-Token"))
	f := newStripTestFlow(map[string]string{
		"Via":           "1.1 proxy",
		"X-Debug-Token": "secret",
		"Accept":        "text/html",
	})
	a.Requestheaders(f)
	if f.Request.Header.Get("Via") != "" {
		t.Error("Via should be stripped")
	}
	if f.Request.Header.Get("X-Debug-Token") != "" {
		t.Error("X-Debug-Token should be stripped")
	}
	if f.Request.Header.Get("Accept") != "text/html" {
		t.Error("Accept should be preserved")
	}
}
func TestStripProxyHeadersReplace(t *testing.T) {
	a := NewStripProxyHeadersAddon(WithStripHeaders("X-Only-This"))
	f := newStripTestFlow(map[string]string{
		"Via":         "1.1 proxy",
		"X-Only-This": "remove-me",
	})
	a.Requestheaders(f)
	// Via should NOT be stripped since we replaced the default list
	if f.Request.Header.Get("Via") != "1.1 proxy" {
		t.Error("Via should be preserved when using WithStripHeaders")
	}
	if f.Request.Header.Get("X-Only-This") != "" {
		t.Error("X-Only-This should be stripped")
	}
}
