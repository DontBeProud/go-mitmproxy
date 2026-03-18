//go:build ignore

// h2-fingerprint — 使用 uTLS + fhttp 同时伪造 TLS 和 HTTP/2 指纹示例
//
// # 背景
//
// go-mitmproxy 默认通过 Go 标准库 crypto/tls 和 x/net/http2 建立到上游服务器的
// TLS + HTTP/2 连接。Go 的 TLS ClientHello 和 HTTP/2 SETTINGS 帧具有独特的指纹，
// 与真实浏览器明显不同，会被部分服务端识别并拒绝服务。
//
// # 解决方案
//
// 1. proxy.WithServerTLSHandshake  — 替换出站 TLS 握手（JA3/JA4 指纹）
// 2. proxy.WithServerH2ClientFactory — 替换出站 HTTP/2 Transport（SETTINGS/WINDOW_UPDATE 指纹）
//
// 本示例展示如何同时注入两者，使代理出站连接的 TLS 和 HTTP/2 指纹与 Chrome 完全一致。
// go-mitmproxy 本身不依赖 utls 或 fhttp；指纹实现完全在调用方侧。
//
// # 运行前准备
//
//  1. 在本示例目录下初始化独立模块（或在你的项目中使用）：
//
//     go mod init example/h2-fingerprint
//     go get github.com/DontBeProud/go-mitmproxy@latest
//     go get github.com/bogdanfinn/utls@latest
//     go get github.com/bogdanfinn/fhttp@latest
//
//  2. 安装代理 CA 证书：
//     启动后访问 http://mitm.it 下载并信任 CA 证书。
//
// # 运行
//
//	go run main.go [-addr :9080] [-ssl-insecure]
//
// # 验证效果
//
//	https://tls.browserleaks.com/tls  — JA3 指纹应显示 Chrome
//	https://tls.peet.ws/api/all       — HTTP/2 SETTINGS 应与 Chrome 一致
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/DontBeProud/go-mitmproxy/addon"
	"github.com/DontBeProud/go-mitmproxy/proxy"
	utls "github.com/bogdanfinn/utls"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr := flag.String("addr", ":9080", "proxy listen address")
	insecure := flag.Bool("ssl-insecure", false, "skip upstream TLS certificate verification")
	verbose := flag.Bool("verbose", false, "print TLS handshake details")
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
	// ── 1. 注入 Chrome uTLS 握手（TLS/JA3 指纹）──────────────────────────
	p.WithServerTLSHandshake(newChromeHandshake(*insecure))
	// ── 2. 注入 Chrome H2 Transport（HTTP/2 SETTINGS 指纹）───────────────
	// 注意：此处仅为示例骨架。实际注入 fhttp 需要在此处创建 fhttp.Transport
	// 并配置 Chrome 的 SETTINGS/WINDOW_UPDATE/PRIORITY 参数。
	// 取消下方注释并引入 fhttp 即可启用。
	//
	// import fhttp "github.com/bogdanfinn/fhttp"
	// import fhttp2 "github.com/bogdanfinn/fhttp/http2"
	//
	// p.WithServerH2ClientFactory(func(tlsConn net.Conn) *http.Client {
	//     return newChromeH2Client(tlsConn)
	// })
	// ── 3. TLS 检查 addon（可选，用于验证指纹注入是否生效）─────────────────
	if *verbose {
		p.AddAddon(addon.NewTLSInspectorAddon(func(info addon.TLSHandshakeInfo) {
			fmt.Printf("[TLS] %-35s proto=%-6s ver=%s cipher=%s resumed=%v\n",
				info.ServerName,
				fmtProto(info.NegotiatedProtocol),
				tlsVerName(info.TLSVersion),
				tls.CipherSuiteName(info.CipherSuite),
				info.DidResume,
			)
		}))
	}
	// ── 4. 普通 addons ──────────────────────────────────────────────────
	p.AddAddon(&proxy.LogAddon{})
	fmt.Printf("proxy listening on %s  (ssl-insecure=%v, verbose=%v)\n",
		*addr, *insecure, *verbose)
	log.Fatal(p.Start())
}

// ── uTLS 握手实现 ────────────────────────────────────────────────────────────
func newChromeHandshake(insecure bool) proxy.ServerTLSHandshakeFunc {
	return func(
		ctx context.Context,
		rawConn net.Conn,
		serverName string,
		clientHello *tls.ClientHelloInfo,
	) (net.Conn, *tls.ConnectionState, error) {
		cfg := &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
		}
		if clientHello != nil && len(clientHello.SupportedProtos) > 0 {
			cfg.NextProtos = clientHello.SupportedProtos
		}
		uConn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto, false, false, false)
		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("utls handshake [%s]: %w", serverName, err)
		}
		us := uConn.ConnectionState()
		state := &tls.ConnectionState{
			Version:                     us.Version,
			HandshakeComplete:           us.HandshakeComplete,
			DidResume:                   us.DidResume,
			CipherSuite:                 us.CipherSuite,
			NegotiatedProtocol:          us.NegotiatedProtocol,
			NegotiatedProtocolIsMutual:  us.NegotiatedProtocolIsMutual,
			ServerName:                  us.ServerName,
			PeerCertificates:            us.PeerCertificates,
			VerifiedChains:              us.VerifiedChains,
			SignedCertificateTimestamps: us.SignedCertificateTimestamps,
			OCSPResponse:                us.OCSPResponse,
		}
		return uConn, state, nil
	}
}

// ── Chrome H2 Client 骨架 ────────────────────────────────────────────────────
//
// newChromeH2Client 返回一个使用已建立的 TLS 连接、配置了 Chrome HTTP/2 指纹的 *http.Client。
// 这里展示基本结构；实际使用时需要引入 bogdanfinn/fhttp 并配置 SETTINGS。
//
//	func newChromeH2Client(tlsConn net.Conn) *http.Client {
//	    // 创建 fhttp Transport，复用已有 TLS 连接
//	    tr := &fhttp.Transport{
//	        DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
//	            return tlsConn, nil
//	        },
//	        ForceAttemptHTTP2:  true,
//	        DisableCompression: true,
//	    }
//	    // 配置 HTTP/2 Transport 以模拟 Chrome SETTINGS
//	    h2tr, _ := fhttp2.ConfigureTransports(tr)
//	    h2tr.Settings = []fhttp2.Setting{
//	        {ID: fhttp2.SettingHeaderTableSize, Val: 65536},
//	        {ID: fhttp2.SettingEnablePush, Val: 0},
//	        {ID: fhttp2.SettingInitialWindowSize, Val: 6291456},
//	        {ID: fhttp2.SettingMaxHeaderListSize, Val: 262144},
//	    }
//	    h2tr.InitialWindowSize = 6291456
//	    h2tr.HeaderTableSize = 65536
//	    return &http.Client{
//	        Transport: tr,
//	        CheckRedirect: func(req *http.Request, via []*http.Request) error {
//	            return http.ErrUseLastResponse
//	        },
//	    }
//	}
//
// ── 格式化辅助 ────────────────────────────────────────────────────────────────
func fmtProto(p string) string {
	if p == "" {
		return "http/1.1"
	}
	return p
}
func tlsVerName(v uint16) string {
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

// Suppress unused import warnings for the skeleton example.
var _ net.Conn
var _ *http.Client
