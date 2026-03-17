// Demonstrates addon.RouterAddon: gin-like routing for every phase of the
// proxy lifecycle (request headers, request body, response headers, response
// body, WebSocket frames, Server-Sent Events).
//
// Run:
//
//	go run .
//
// Then configure your browser/tool to use HTTP proxy at localhost:9080.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lqqyt2423/go-mitmproxy/addon"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

func main() {
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	r := addon.NewRouterAddon()
	registerRoutes(r)
	p.AddAddon(r)

	fmt.Println("proxy listening on :9080")
	log.Fatal(p.Start())
}

func registerRoutes(r *addon.RouterAddon) {
	// -------------------------------------------------------------------------
	// OnRequestHeaders – fires before the request body is read.
	// Useful for early blocking/redirecting without buffering the body.
	// -------------------------------------------------------------------------
	r.OnRequestHeaders().Host("httpbin.org").GET("/status/:code", func(c *addon.FlowContext) {
		log.Infof("[RequestHeaders] GET httpbin.org/status/%s", c.Param("code"))
	})

	// -------------------------------------------------------------------------
	// OnRequest – fires after the full request body is available.
	// -------------------------------------------------------------------------

	// Inject an extra header into every POST on api.example.com.
	r.OnRequest().Host("api.example.com").POST("/v1/*path", func(c *addon.FlowContext) {
		c.Request.Header.Set("X-Injected", "go-mitmproxy")
		log.Infof("[Request] injected header → POST api.example.com/v1/%s", c.Param("path"))
	})

	// Intercept a specific endpoint and return a mocked response immediately,
	// without forwarding to the upstream server.
	r.OnRequest().Host("httpbin.org").GET("/get", func(c *addon.FlowContext) {
		body, _ := json.Marshal(map[string]string{"mocked": "true", "by": "go-mitmproxy"})
		c.Response = &proxy.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       body,
		}
		log.Infof("[Request] mocked response for GET httpbin.org/get")
	})

	// -------------------------------------------------------------------------
	// OnResponseHeaders – fires before the response body is read.
	// Useful for logging status codes or early decisions.
	// -------------------------------------------------------------------------
	r.OnResponseHeaders().Host("httpbin.org").ANY("/", func(c *addon.FlowContext) {
		if c.Response != nil {
			log.Infof("[ResponseHeaders] %s %s → %d",
				c.Request.Method, c.Request.URL.Path, c.Response.StatusCode)
		}
	})

	// -------------------------------------------------------------------------
	// OnResponse – fires after the full response body is available.
	// -------------------------------------------------------------------------

	// Rewrite a JSON response field.
	r.OnResponse().Host("httpbin.org").GET("/json", func(c *addon.FlowContext) {
		if c.Response == nil || len(c.Response.Body) == 0 {
			return
		}
		var data map[string]interface{}
		if err := json.Unmarshal(c.Response.Body, &data); err != nil {
			return
		}
		data["injected_by"] = "go-mitmproxy"
		if patched, err := json.Marshal(data); err == nil {
			c.Response.Body = patched
			log.Infof("[Response] patched JSON body for GET httpbin.org/json")
		}
	})

	// Group example: all routes under httpbin.org/anything share a logging middleware.
	anything := r.OnResponse().Host("httpbin.org").Group("/anything").Use(func(c *addon.FlowContext) {
		log.Infof("[Response:middleware] %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})
	anything.GET("/:name", func(c *addon.FlowContext) {
		log.Infof("[Response] GET /anything/%s status=%d", c.Param("name"), c.Response.StatusCode)
	})

	// -------------------------------------------------------------------------
	// OnWebSocket – fires for each WebSocket frame.
	// Routes by the original HTTP upgrade request URL.
	// -------------------------------------------------------------------------
	r.OnWebSocket().Host("echo.websocket.org").GET("/", func(c *addon.FlowContext) {
		if c.WebScoket == nil || len(c.WebScoket.Messages) == 0 {
			return
		}
		last := c.WebScoket.Messages[len(c.WebScoket.Messages)-1]
		dir := "C→S"
		if !last.FromClient {
			dir = "S→C"
		}
		log.Infof("[WebSocket] %s frame len=%d", dir, len(last.Content))
	})

	// -------------------------------------------------------------------------
	// OnSSE – fires for each Server-Sent Event.
	// Routes by the original request URL.
	// -------------------------------------------------------------------------
	r.OnSSE().Host("api.example.com").GET("/events", func(c *addon.FlowContext) {
		if c.SSE == nil || len(c.SSE.Events) == 0 {
			return
		}
		ev := c.SSE.Events[len(c.SSE.Events)-1]
		log.Infof("[SSE] event=%q id=%s data_len=%d", ev.Event, ev.ID, len(ev.Data))
	})
}

