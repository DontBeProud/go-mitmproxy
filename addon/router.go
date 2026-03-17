package addon

import (
	"regexp"
	"sync"

	"github.com/DontBeProud/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

// FlowHandlerFunc is the handler signature, similar to gin.HandlerFunc.
type FlowHandlerFunc func(*FlowContext)

// FlowContext wraps proxy.Flow with a gin-like handler chain and path params.
type FlowContext struct {
	*proxy.Flow
	Params   map[string]string
	handlers []FlowHandlerFunc
	index    int
	abort    bool
}

// Next executes the next handler in the chain.
func (c *FlowContext) Next() {
	c.index++
	for c.index < len(c.handlers) && !c.abort {
		c.handlers[c.index](c)
		c.index++
	}
}

// Abort stops the handler chain.
func (c *FlowContext) Abort() {
	c.abort = true
}

// IsAborted returns whether Abort has been called.
func (c *FlowContext) IsAborted() bool {
	return c.abort
}

// Param returns the named path parameter (e.g. ":id").
func (c *FlowContext) Param(key string) string {
	return c.Params[key]
}

// flowRoute is a single registered route entry.
type flowRoute struct {
	method     string
	hostRegex  *regexp.Regexp
	pathRegex  *regexp.Regexp
	paramNames []string
	handlers   []FlowHandlerFunc
}

var matchAllHostRegex = regexp.MustCompile(`.*`)

// FlowRouter dispatches proxy flows to handlers by host/method/path pattern,
// similar to gin's Router. An empty host matches any host.
//
// Pattern syntax:
//   - :name  matches a single path/host segment, captured as Param("name")
//   - *name  matches the rest of the path, captured as Param("name")
//   - *      wildcard in host, matches a single label (e.g. "*.example.com")
type FlowRouter struct {
	mu             sync.RWMutex
	globalHandlers []FlowHandlerFunc
	routes         []*flowRoute
}

func NewFlowRouter() *FlowRouter {
	return &FlowRouter{}
}

// Use registers global middleware executed for every flow regardless of route match.
func (r *FlowRouter) Use(handlers ...FlowHandlerFunc) {
	r.globalHandlers = append(r.globalHandlers, handlers...)
}

func (r *FlowRouter) addRoute(host, method, path string, handlers ...FlowHandlerFunc) {
	pathRegex, paramNames := compilePathPattern(path)
	r.mu.Lock()
	r.routes = append(r.routes, &flowRoute{
		method:     method,
		hostRegex:  compileHostPattern(host),
		pathRegex:  pathRegex,
		paramNames: paramNames,
		handlers:   handlers,
	})
	r.mu.Unlock()
}

// --- Per-method registration (any host) ---

func (r *FlowRouter) GET(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "GET", path, handlers...)
}

func (r *FlowRouter) POST(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "POST", path, handlers...)
}

func (r *FlowRouter) PUT(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "PUT", path, handlers...)
}

func (r *FlowRouter) DELETE(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "DELETE", path, handlers...)
}

func (r *FlowRouter) PATCH(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "PATCH", path, handlers...)
}

func (r *FlowRouter) HEAD(path string, handlers ...FlowHandlerFunc) {
	r.addRoute("", "HEAD", path, handlers...)
}

// ANY registers all common HTTP methods for the given path on any host.
func (r *FlowRouter) ANY(path string, handlers ...FlowHandlerFunc) {
	for _, m := range httpMethods {
		r.addRoute("", m, path, handlers...)
	}
}

// Host returns a FlowGroup scoped to the given host pattern.
//
//	router.Host("api.example.com").GET("/users", handler)
//	router.Host("*.example.com").ANY("/", handler)
func (r *FlowRouter) Host(host string) *FlowGroup {
	return &FlowGroup{router: r, host: host}
}

// Group creates a route group with a shared path prefix and optional middleware.
func (r *FlowRouter) Group(prefix string, handlers ...FlowHandlerFunc) *FlowGroup {
	h := make([]FlowHandlerFunc, len(handlers))
	copy(h, handlers)
	return &FlowGroup{router: r, prefix: prefix, handlers: h}
}

// HandleFlow matches the flow against registered routes and executes the handler chain.
func (r *FlowRouter) HandleFlow(f *proxy.Flow) {
	if f.Request == nil || f.Request.URL == nil {
		return
	}

	r.mu.RLock()
	hasGlobal := len(r.globalHandlers) > 0
	hasRoutes := len(r.routes) > 0
	r.mu.RUnlock()

	if !hasGlobal && !hasRoutes {
		return
	}

	method := f.Request.Method
	host := f.Request.URL.Hostname()
	path := f.Request.URL.Path

	r.mu.RLock()
	handlers := make([]FlowHandlerFunc, len(r.globalHandlers))
	copy(handlers, r.globalHandlers)

	var matchedParams map[string]string
	for _, route := range r.routes {
		if route.method != method {
			continue
		}
		if !route.hostRegex.MatchString(host) {
			continue
		}
		matches := route.pathRegex.FindStringSubmatch(path)
		if matches == nil {
			continue
		}
		matchedParams = make(map[string]string, len(route.paramNames))
		for i, name := range route.paramNames {
			if i+1 < len(matches) {
				matchedParams[name] = matches[i+1]
			}
		}
		handlers = append(handlers, route.handlers...)
		break
	}
	r.mu.RUnlock()

	if len(handlers) == 0 {
		return
	}

	if matchedParams == nil {
		matchedParams = map[string]string{}
	}
	ctx := &FlowContext{
		Flow:     f,
		Params:   matchedParams,
		handlers: handlers,
		index:    -1,
	}

	defer func() {
		if err := recover(); err != nil {
			log.Errorf("FlowRouter handler panic: %v", err)
		}
	}()

	ctx.Next()
}

// --- FlowGroup ---

// FlowGroup is a set of routes sharing a host filter, path prefix, and middleware.
type FlowGroup struct {
	router   *FlowRouter
	host     string
	prefix   string
	handlers []FlowHandlerFunc
}

// Use adds middleware to this group.
// Returns a new FlowGroup to avoid mutating siblings.
func (g *FlowGroup) Use(handlers ...FlowHandlerFunc) *FlowGroup {
	all := make([]FlowHandlerFunc, 0, len(g.handlers)+len(handlers))
	all = append(all, g.handlers...)
	all = append(all, handlers...)
	return &FlowGroup{router: g.router, host: g.host, prefix: g.prefix, handlers: all}
}

// Group creates a nested sub-group inheriting the parent's host and middleware.
func (g *FlowGroup) Group(prefix string, handlers ...FlowHandlerFunc) *FlowGroup {
	all := make([]FlowHandlerFunc, 0, len(g.handlers)+len(handlers))
	all = append(all, g.handlers...)
	all = append(all, handlers...)
	return &FlowGroup{router: g.router, host: g.host, prefix: g.prefix + prefix, handlers: all}
}

func (g *FlowGroup) addRoute(method, path string, handlers ...FlowHandlerFunc) {
	all := make([]FlowHandlerFunc, 0, len(g.handlers)+len(handlers))
	all = append(all, g.handlers...)
	all = append(all, handlers...)
	g.router.addRoute(g.host, method, g.prefix+path, all...)
}

func (g *FlowGroup) GET(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("GET", path, handlers...)
}

func (g *FlowGroup) POST(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("POST", path, handlers...)
}

func (g *FlowGroup) PUT(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("PUT", path, handlers...)
}

func (g *FlowGroup) DELETE(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("DELETE", path, handlers...)
}

func (g *FlowGroup) PATCH(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("PATCH", path, handlers...)
}

func (g *FlowGroup) HEAD(path string, handlers ...FlowHandlerFunc) {
	g.addRoute("HEAD", path, handlers...)
}

func (g *FlowGroup) ANY(path string, handlers ...FlowHandlerFunc) {
	for _, m := range httpMethods {
		g.addRoute(m, path, handlers...)
	}
}

// --- Pattern helpers ---

var httpMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

// compileHostPattern builds a regex for host matching.
//   - ""              → matches any host
//   - "example.com"   → exact match
//   - "*.example.com" → single-label wildcard
func compileHostPattern(host string) *regexp.Regexp {
	if host == "" {
		return matchAllHostRegex
	}
	var buf []byte
	buf = append(buf, '^')
	for i := 0; i < len(host); i++ {
		switch {
		case host[i] == '*':
			buf = append(buf, `[^.]*`...)
		case host[i] == ':':
			j := i + 1
			for j < len(host) && host[j] != '.' {
				j++
			}
			buf = append(buf, `[^.]+`...)
			i = j - 1
		default:
			buf = appendRegexLiteral(buf, host[i])
		}
	}
	buf = append(buf, '$')
	return regexp.MustCompile(string(buf))
}

// compilePathPattern builds a regex for path matching and extracts param names.
//   - /users/:id   → /users/([^/]+),  param "id"
//   - /files/*path → /files/(.*),     param "path"
func compilePathPattern(path string) (*regexp.Regexp, []string) {
	var buf []byte
	var names []string
	buf = append(buf, '^')
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case ':':
			j := i + 1
			for j < len(path) && path[j] != '/' {
				j++
			}
			names = append(names, path[i+1:j])
			buf = append(buf, `([^/]+)`...)
			i = j - 1
		case '*':
			j := i + 1
			for j < len(path) && path[j] != '/' {
				j++
			}
			if j > i+1 {
				names = append(names, path[i+1:j])
			}
			buf = append(buf, `(.*)`...)
			i = j - 1
		default:
			buf = appendRegexLiteral(buf, path[i])
		}
	}
	buf = append(buf, '$')
	return regexp.MustCompile(string(buf)), names
}

// appendRegexLiteral escapes a byte if it is a regex meta character.
func appendRegexLiteral(buf []byte, ch byte) []byte {
	const metaChars = `.+?()[]{}\\^$|*`
	for i := 0; i < len(metaChars); i++ {
		if ch == metaChars[i] {
			return append(buf, '\\', ch)
		}
	}
	return append(buf, ch)
}
