package addon

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/DontBeProud/go-mitmproxy/proxy"
)

func newTestFlow(method, host, path string) *proxy.Flow {
	f := &proxy.Flow{}
	f.Request = &proxy.Request{
		Method: method,
		URL:    &url.URL{Scheme: "https", Host: host, Path: path},
		Header: make(http.Header),
	}
	return f
}

// --- Pattern compile tests ---

func TestCompileHostPattern(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		match   bool
	}{
		{"", "anything.example.com", true},
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.api.example.com", false},
		// regex meta chars in host must be escaped
		{"my-host.example.com", "my-host.example.com", true},
		{"my-host.example.com", "myXhost.example.com", false}, // '-' should be literal, not regex range
	}
	for _, tt := range tests {
		re := compileHostPattern(tt.pattern)
		got := re.MatchString(tt.host)
		if got != tt.match {
			t.Errorf("compileHostPattern(%q).MatchString(%q) = %v, want %v", tt.pattern, tt.host, got, tt.match)
		}
	}
}

func TestCompilePathPattern(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
		params  map[string]string
	}{
		{"/users", "/users", true, nil},
		{"/users", "/users/1", false, nil},
		{"/users/:id", "/users/42", true, map[string]string{"id": "42"}},
		{"/users/:id/posts/:pid", "/users/1/posts/2", true, map[string]string{"id": "1", "pid": "2"}},
		{"/files/*path", "/files/a/b/c", true, map[string]string{"path": "a/b/c"}},
		// regex meta chars in literal path
		{"/v1.0/api", "/v1.0/api", true, nil},
		{"/v1.0/api", "/v1X0/api", false, nil},
	}
	for _, tt := range tests {
		re, names := compilePathPattern(tt.pattern)
		matches := re.FindStringSubmatch(tt.path)
		gotMatch := matches != nil
		if gotMatch != tt.match {
			t.Errorf("compilePathPattern(%q) match %q = %v, want %v (regex=%s)", tt.pattern, tt.path, gotMatch, tt.match, re.String())
			continue
		}
		if !gotMatch || tt.params == nil {
			continue
		}
		for _, name := range names {
			for i, n := range names {
				if n == name && i+1 < len(matches) {
					if matches[i+1] != tt.params[name] {
						t.Errorf("param %q = %q, want %q", name, matches[i+1], tt.params[name])
					}
				}
			}
		}
	}
}

// --- Router matching tests ---

func TestRouterBasicMatch(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.GET("/hello", func(c *FlowContext) { called = true })

	f := newTestFlow("GET", "any.host", "/hello")
	r.HandleFlow(f)
	if !called {
		t.Fatal("handler not called")
	}
}

func TestRouterNoMatchSkips(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.GET("/hello", func(c *FlowContext) { called = true })

	f := newTestFlow("GET", "any.host", "/world")
	r.HandleFlow(f)
	if called {
		t.Fatal("handler should not be called for non-matching path")
	}
}

func TestRouterMethodMismatch(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.POST("/hello", func(c *FlowContext) { called = true })

	f := newTestFlow("GET", "any.host", "/hello")
	r.HandleFlow(f)
	if called {
		t.Fatal("POST handler should not fire for GET")
	}
}

func TestRouterHostMatch(t *testing.T) {
	r := NewFlowRouter()
	var result string
	r.Host("api.example.com").GET("/data", func(c *FlowContext) { result = "api" })
	r.Host("web.example.com").GET("/data", func(c *FlowContext) { result = "web" })

	f := newTestFlow("GET", "web.example.com", "/data")
	r.HandleFlow(f)
	if result != "web" {
		t.Fatalf("got %q, want %q", result, "web")
	}
}

func TestRouterWildcardHost(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.Host("*.example.com").GET("/", func(c *FlowContext) { called = true })

	f := newTestFlow("GET", "api.example.com", "/")
	r.HandleFlow(f)
	if !called {
		t.Fatal("wildcard host should match")
	}
}

func TestRouterParams(t *testing.T) {
	r := NewFlowRouter()
	var gotID string
	r.GET("/users/:id", func(c *FlowContext) { gotID = c.Param("id") })

	f := newTestFlow("GET", "host", "/users/123")
	r.HandleFlow(f)
	if gotID != "123" {
		t.Fatalf("got %q, want %q", gotID, "123")
	}
}

func TestRouterCatchAll(t *testing.T) {
	r := NewFlowRouter()
	var gotPath string
	r.GET("/files/*filepath", func(c *FlowContext) { gotPath = c.Param("filepath") })

	f := newTestFlow("GET", "host", "/files/a/b/c.txt")
	r.HandleFlow(f)
	if gotPath != "a/b/c.txt" {
		t.Fatalf("got %q, want %q", gotPath, "a/b/c.txt")
	}
}

func TestRouterANY(t *testing.T) {
	r := NewFlowRouter()
	count := 0
	r.ANY("/any", func(c *FlowContext) { count++ })

	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		r.HandleFlow(newTestFlow(m, "h", "/any"))
	}
	if count != 7 {
		t.Fatalf("ANY should match 7 methods, got %d", count)
	}
}

// --- Middleware & chain tests ---

func TestGlobalMiddleware(t *testing.T) {
	r := NewFlowRouter()
	var order []string
	r.Use(func(c *FlowContext) {
		order = append(order, "global")
		c.Next()
	})
	r.GET("/x", func(c *FlowContext) { order = append(order, "handler") })

	r.HandleFlow(newTestFlow("GET", "h", "/x"))
	if len(order) != 2 || order[0] != "global" || order[1] != "handler" {
		t.Fatalf("unexpected order: %v", order)
	}
}

func TestGlobalMiddlewareNoRouteMatch(t *testing.T) {
	r := NewFlowRouter()
	var globalCalled bool
	r.Use(func(c *FlowContext) { globalCalled = true })
	r.GET("/x", func(c *FlowContext) {})

	r.HandleFlow(newTestFlow("GET", "h", "/no-match"))
	if !globalCalled {
		t.Fatal("global middleware should run even without route match")
	}
}

func TestAbort(t *testing.T) {
	r := NewFlowRouter()
	var order []string
	r.Use(func(c *FlowContext) {
		order = append(order, "mw")
		c.Abort()
	})
	r.GET("/x", func(c *FlowContext) { order = append(order, "handler") })

	r.HandleFlow(newTestFlow("GET", "h", "/x"))
	if len(order) != 1 || order[0] != "mw" {
		t.Fatalf("Abort should stop chain, got: %v", order)
	}
}

func TestIsAborted(t *testing.T) {
	r := NewFlowRouter()
	var aborted bool
	r.GET("/x", func(c *FlowContext) {
		c.Abort()
		aborted = c.IsAborted()
	})
	r.HandleFlow(newTestFlow("GET", "h", "/x"))
	if !aborted {
		t.Fatal("IsAborted should return true")
	}
}

// --- Group tests ---

func TestGroupPrefix(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	g := r.Group("/api/v1")
	g.GET("/users", func(c *FlowContext) { called = true })

	r.HandleFlow(newTestFlow("GET", "h", "/api/v1/users"))
	if !called {
		t.Fatal("group prefix route not matched")
	}
}

func TestGroupMiddleware(t *testing.T) {
	r := NewFlowRouter()
	var order []string
	g := r.Group("/api", func(c *FlowContext) {
		order = append(order, "group-mw")
		c.Next()
	})
	g.GET("/data", func(c *FlowContext) { order = append(order, "handler") })

	r.HandleFlow(newTestFlow("GET", "h", "/api/data"))
	if len(order) != 2 || order[0] != "group-mw" || order[1] != "handler" {
		t.Fatalf("unexpected order: %v", order)
	}
}

func TestGroupUseReturnsNewGroup(t *testing.T) {
	r := NewFlowRouter()
	base := r.Host("h.com").Group("/api")

	var mwCalled bool
	withMw := base.Use(func(c *FlowContext) {
		mwCalled = true
		c.Next()
	})

	var baseCalled bool
	base.GET("/plain", func(c *FlowContext) { baseCalled = true })

	var withMwCalled bool
	withMw.GET("/rich", func(c *FlowContext) { withMwCalled = true })

	// call /api/plain → should NOT trigger the middleware
	r.HandleFlow(newTestFlow("GET", "h.com", "/api/plain"))
	if !baseCalled {
		t.Fatal("base route not matched")
	}
	if mwCalled {
		t.Fatal("Use() should NOT mutate original group; middleware should not run for base group routes")
	}

	// call /api/rich → should trigger the middleware
	r.HandleFlow(newTestFlow("GET", "h.com", "/api/rich"))
	if !withMwCalled {
		t.Fatal("withMw route not matched")
	}
	if !mwCalled {
		t.Fatal("middleware should run for withMw group routes")
	}
}

func TestNestedGroup(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	api := r.Group("/api")
	v2 := api.Group("/v2")
	v2.GET("/items", func(c *FlowContext) { called = true })

	r.HandleFlow(newTestFlow("GET", "h", "/api/v2/items"))
	if !called {
		t.Fatal("nested group route not matched")
	}
}

func TestGroupWithHost(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.Host("secure.io").Group("/v1").GET("/check", func(c *FlowContext) { called = true })

	// wrong host
	r.HandleFlow(newTestFlow("GET", "other.io", "/v1/check"))
	if called {
		t.Fatal("should not match wrong host")
	}

	// correct host
	r.HandleFlow(newTestFlow("GET", "secure.io", "/v1/check"))
	if !called {
		t.Fatal("should match correct host")
	}
}

// --- Nil/empty safety ---

func TestHandleFlowNilRequest(t *testing.T) {
	r := NewFlowRouter()
	r.GET("/x", func(c *FlowContext) {})
	r.HandleFlow(&proxy.Flow{}) // should not panic
}

func TestHandleFlowEmptyRouter(t *testing.T) {
	r := NewFlowRouter()
	r.HandleFlow(newTestFlow("GET", "h", "/x")) // should not panic, no-op
}

// --- Panic recovery ---

func TestHandlerPanicRecovery(t *testing.T) {
	r := NewFlowRouter()
	r.GET("/boom", func(c *FlowContext) { panic("test panic") })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic leaked out of HandleFlow: %v", r)
		}
	}()
	r.HandleFlow(newTestFlow("GET", "h", "/boom"))
}

// --- Regex escape ---

func TestHostWithHyphen(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.Host("my-api.example.com").GET("/", func(c *FlowContext) { called = true })

	// "my-api" should be literal, not regex char class
	r.HandleFlow(newTestFlow("GET", "myXapi.example.com", "/"))
	if called {
		t.Fatal("hyphen in host pattern should be literal, not regex range")
	}

	r.HandleFlow(newTestFlow("GET", "my-api.example.com", "/"))
	if !called {
		t.Fatal("literal hyphen host should match")
	}
}

func TestPathWithDot(t *testing.T) {
	r := NewFlowRouter()
	var called bool
	r.GET("/v1.0/api", func(c *FlowContext) { called = true })

	r.HandleFlow(newTestFlow("GET", "h", "/v1X0/api"))
	if called {
		t.Fatal("dot in path pattern should be literal")
	}

	r.HandleFlow(newTestFlow("GET", "h", "/v1.0/api"))
	if !called {
		t.Fatal("literal dot path should match")
	}
}

// --- First match wins ---

func TestFirstMatchWins(t *testing.T) {
	r := NewFlowRouter()
	var result string
	r.GET("/items/:id", func(c *FlowContext) { result = "param:" + c.Param("id") })
	r.GET("/items/special", func(c *FlowContext) { result = "special" })

	r.HandleFlow(newTestFlow("GET", "h", "/items/special"))
	if result != "param:special" {
		t.Fatalf("first match should win, got %q", result)
	}
}
