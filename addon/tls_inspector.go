package addon

// tls_inspector.go — TLS 握手结果检查 Addon
//
// TLSInspectorAddon 在每次出站 TLS 握手完成后（TlsEstablishedServer 钩子）触发
// 一个用户提供的回调，让调用方能观测实际协商的 TLS 参数（版本、密码套件、ALPN
// 协议等），而无需关心代理内部实现。
//
// 典型用途：
//  1. 验证 uTLS 指纹注入是否生效（协商版本/密码套件应与目标 Chrome Profile 一致）
//  2. 监控 / 打点指定域名的 TLS 握手状态
//  3. 断言测试中确认 ALPN 协商结果为 "h2"
//
// 该 addon 无任何外部依赖，可与 proxy.WithServerTLSHandshake 配合使用，也可独立
// 添加到未注入自定义握手的代理实例上。
//
// 示例：
//
//	p.AddAddon(addon.NewTLSInspectorAddon(func(info addon.TLSHandshakeInfo) {
//	    log.Printf("[TLS] %-30s proto=%-6s ver=0x%04x cipher=%s resumed=%v",
//	        info.ServerName, info.NegotiatedProtocol,
//	        info.TLSVersion, tls.CipherSuiteName(info.CipherSuite), info.DidResume)
//	}))

import (
	"crypto/tls"

	"github.com/DontBeProud/go-mitmproxy/proxy"
	log "github.com/sirupsen/logrus"
)

// TLSHandshakeInfo 包含一次出站 TLS 握手完成后的可观测字段。
// 所有字段来自 *tls.ConnectionState，与底层实现（crypto/tls 或 uTLS）无关。
type TLSHandshakeInfo struct {
	// ServerName 是本次握手的 SNI，通常等于目标域名。
	ServerName string

	// NegotiatedProtocol 是 ALPN 协商结果，例如 "h2" 或 "http/1.1"。
	// 为空表示服务端未通过 ALPN 选择协议。
	NegotiatedProtocol string

	// TLSVersion 是协商的 TLS 版本号（例如 tls.VersionTLS13 = 0x0304）。
	TLSVersion uint16

	// CipherSuite 是协商的密码套件 ID（例如 tls.TLS_AES_128_GCM_SHA256）。
	// 可用 tls.CipherSuiteName(info.CipherSuite) 获取可读名称。
	CipherSuite uint16

	// DidResume 为 true 表示本次握手复用了之前的 TLS Session（session ticket）。
	DidResume bool
}

// TLSInspectorAddon 在每次出站 TLS 握手完成后触发回调。
// 零值可用（回调为 nil 时仅以 DEBUG 级别打日志）。
// 通过 NewTLSInspectorAddon 构造更推荐。
type TLSInspectorAddon struct {
	proxy.BaseAddon

	// onHandshake 是握手完成后的回调，在 TlsEstablishedServer 钩子中同步调用。
	// 若为 nil，则使用内置的 logrus DEBUG 日志。
	onHandshake func(TLSHandshakeInfo)
}

// NewTLSInspectorAddon 创建一个握手结果检查 addon。
//
//	fn  每次握手完成后被调用，参数为本次握手信息。传 nil 退化为内置 DEBUG 日志。
func NewTLSInspectorAddon(fn func(TLSHandshakeInfo)) *TLSInspectorAddon {
	return &TLSInspectorAddon{onHandshake: fn}
}

// TlsEstablishedServer 实现 proxy.Addon 接口，在出站 TLS 握手完成时被代理调用。
func (a *TLSInspectorAddon) TlsEstablishedServer(connCtx *proxy.ConnContext) {
	state := connCtx.ServerConn.TlsState()
	if state == nil {
		return
	}

	info := TLSHandshakeInfo{
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
		TLSVersion:         state.Version,
		CipherSuite:        state.CipherSuite,
		DidResume:          state.DidResume,
	}

	if a.onHandshake != nil {
		a.onHandshake(info)
		return
	}

	// 默认行为：DEBUG 日志
	log.WithFields(log.Fields{
		"server":  info.ServerName,
		"proto":   info.NegotiatedProtocol,
		"version": tlsVersionName(info.TLSVersion),
		"cipher":  tls.CipherSuiteName(info.CipherSuite),
		"resumed": info.DidResume,
	}).Debug("TLS handshake established")
}

// tlsVersionName 返回 TLS 版本的可读名称。
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
		return "unknown"
	}
}
