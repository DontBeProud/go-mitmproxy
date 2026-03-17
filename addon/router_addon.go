package addon

import "github.com/DontBeProud/go-mitmproxy/proxy"

// RouterAddon integrates FlowRouter into the proxy addon system.
// Each hook stage that carries a *Flow and a meaningful URL has its own router,
// giving callers gin-like routing for every phase of the HTTP/WebSocket/SSE lifecycle.
//
// Routable stages (receive *Flow with URL + method):
//
//	OnRequestHeaders  → Requestheaders  – headers received, body not yet read
//	OnRequest         → Request         – full request body available
//	OnResponseHeaders → Responseheaders – response headers received, body not yet read
//	OnResponse        → Response        – full response body available
//	OnWebSocket       → WebSocketMessage – each WebSocket frame
//	OnSSE             → SSEMessage       – each Server-Sent Event
//
// Non-routable stages (no URL or non-Flow signature) are left to the caller via
// proxy.BaseAddon embedding: ClientConnected/Disconnected, ServerConnected/Disconnected,
// TlsEstablishedServer, StreamRequestModifier, StreamResponseModifier, AccessProxyServer.
type RouterAddon struct {
	proxy.BaseAddon
	onRequestHeaders  *FlowRouter
	onRequest         *FlowRouter
	onResponseHeaders *FlowRouter
	onResponse        *FlowRouter
	onWebSocket       *FlowRouter
	onSSE             *FlowRouter
}

func NewRouterAddon() *RouterAddon {
	return &RouterAddon{
		onRequestHeaders:  NewFlowRouter(),
		onRequest:         NewFlowRouter(),
		onResponseHeaders: NewFlowRouter(),
		onResponse:        NewFlowRouter(),
		onWebSocket:       NewFlowRouter(),
		onSSE:             NewFlowRouter(),
	}
}

// OnRequestHeaders returns the router for the Requestheaders hook.
// Headers are available; body has not been read yet.
func (a *RouterAddon) OnRequestHeaders() *FlowRouter { return a.onRequestHeaders }

// OnRequest returns the router for the Request hook.
// Full request body is available.
func (a *RouterAddon) OnRequest() *FlowRouter { return a.onRequest }

// OnResponseHeaders returns the router for the Responseheaders hook.
// Response headers are available; body has not been read yet.
func (a *RouterAddon) OnResponseHeaders() *FlowRouter { return a.onResponseHeaders }

// OnResponse returns the router for the Response hook.
// Full response body is available.
func (a *RouterAddon) OnResponse() *FlowRouter { return a.onResponse }

// OnWebSocket returns the router for the WebSocketMessage hook.
// Fired for each WebSocket frame; routes by the original upgrade request URL.
func (a *RouterAddon) OnWebSocket() *FlowRouter { return a.onWebSocket }

// OnSSE returns the router for the SSEMessage hook.
// Fired for each Server-Sent Event; routes by the original request URL.
func (a *RouterAddon) OnSSE() *FlowRouter { return a.onSSE }

// --- proxy.Addon implementation ---

func (a *RouterAddon) Requestheaders(f *proxy.Flow)   { a.onRequestHeaders.HandleFlow(f) }
func (a *RouterAddon) Request(f *proxy.Flow)          { a.onRequest.HandleFlow(f) }
func (a *RouterAddon) Responseheaders(f *proxy.Flow)  { a.onResponseHeaders.HandleFlow(f) }
func (a *RouterAddon) Response(f *proxy.Flow)         { a.onResponse.HandleFlow(f) }
func (a *RouterAddon) WebSocketMessage(f *proxy.Flow) { a.onWebSocket.HandleFlow(f) }
func (a *RouterAddon) SSEMessage(f *proxy.Flow)       { a.onSSE.HandleFlow(f) }
