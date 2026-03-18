//go:build ignore

// utls-fingerprint — 使用 uTLS 伪造出站 TLS 指纹示例
//
// # 背景
//
// go-mitmproxy 默认通过 Go 标准库 crypto/tls 建立到上游服务器的 TLS 连接。
// Go 的 TLS ClientHello 具有独特的 JA3/JA4 指纹，与真实浏览器明显不同，
// 会被部分服务端（如网易藏宝阁 CBG）识别并拒绝服务（返回 303 跳转维护页）。
//
// # 解决方案
//
// proxy.WithServerTLSHandshake 暴露了出站 TLS 握手插件点：
// 调用方只需提供一个实现了 proxy.ServerTLSHandshakeFunc 签名的函数，
// 代理就会在每次连接上游服务器时调用它来完成 TLS 握手，完全替代内置的 crypto/tls 路径。
//
// 本示例展示如何用 bogdanfinn/utls 注入 Chrome 浏览器的 TLS 指纹。
// go-mitmproxy 本身不依赖任何 uTLS 库，指纹实现完全在调用方侧。
//
// # 运行前准备
//
//  1. 在本示例目录下初始化独立模块（或在你的项目中使用）：
//
//     go mod init example/utls-fingerprint
//     go get github.com/DontBeProud/go-mitmproxy@latest
//     go get github.com/bogdanfinn/utls@latest
//
//  2. 安装代理 CA 证书：
//     启动后访问 http://mitm.it 或 http://localhost:<port>/cert 下载并信任 CA 证书。
//
// # 运行
//
//	go run main.go [-addr :9080] [-ssl-insecure] [-verbose]
//
// # 验证效果
//
// 将浏览器代理设置为本地监听地址，然后访问：
//
//	https://tls.browserleaks.com/tls        — 查看 JA3 指纹（应显示 Chrome 指纹）
//	https://xyq-m.cbg.163.com/             — CBG 应正常返回 200 而非 303 跳转
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"

	"github.com/DontBeProud/go-mitmproxy/addon"
	"github.com/DontBeProud/go-mitmproxy/proxy"
	utls "github.com/bogdanfinn/utls"
	log "github.com/sirupsen/logrus"
)

func main() {
	addr := flag.String("addr", ":9080", "proxy listen address")
	insecure := flag.Bool("ssl-insecure", false, "skip upstream TLS certificate verification")
	verbose := flag.Bool("verbose", false, "print TLS handshake details for every upstream connection")
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

	// ── 1. 注入 Chrome uTLS 握手 ────────────────────────────────────────────
	// WithServerTLSHandshake 替换 go-mitmproxy 出站 TLS 握手的全部逻辑。
	// go-mitmproxy 本身不依赖 utls；指纹实现完全由此处的闭包承担。
	p.WithServerTLSHandshake(newChromeHandshake(*insecure))

	// ── 2. 添加 TLS 检查 addon（可选，用于验证指纹注入是否生效）───────────────
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

	// ── 3. 普通 addons ────────────────────────────────────────────────────────
	p.AddAddon(&proxy.LogAddon{})

	fmt.Printf("proxy listening on %s  (ssl-insecure=%v, verbose=%v)\n",
		*addr, *insecure, *verbose)
	log.Fatal(p.Start())
}

// ── uTLS 握手实现 ─────────────────────────────────────────────────────────────

// newChromeHandshake 返回一个 proxy.ServerTLSHandshakeFunc，使用
// bogdanfinn/utls Chrome_Auto（当前库最新 Chrome Profile）完成出站 TLS 握手。
//
// 函数签名与 proxy.ServerTLSHandshakeFunc 完全对应：
//   - ctx         – 上下文（超时/取消传播至握手过程）
//   - rawConn     – 已建立的 TCP 连接（go-mitmproxy 传入）
//   - serverName  – SNI，来自浏览器 ClientHello
//   - clientHello – 浏览器原始 ClientHello（用于镜像 ALPN 等协商参数）
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
		// 镜像浏览器协商的 ALPN，确保 h2 能正确协商
		if clientHello != nil && len(clientHello.SupportedProtos) > 0 {
			cfg.NextProtos = clientHello.SupportedProtos
		}

		// HelloChrome_Auto 始终指向该库支持的最新 Chrome Profile。
		// 如需锁定版本，可改用 utls.HelloChrome_133 等具名常量。
		//
		// 参数说明：
		//   withRandomTLSExtensionOrder = false → 确定性扩展顺序，精准匹配 Chrome 指纹
		//   withForceHttp1              = false → 允许 h2 协商
		//   withDisableHttp3            = false → 不禁用 QUIC（TCP 连接上无效，可设任意值）
		uConn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto, false, false, false)

		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("utls handshake [%s]: %w", serverName, err)
		}

		// utls.ConnectionState 与 crypto/tls.ConnectionState 结构相同但多了 ALPS 字段，
		// 无法直接类型转换，手动映射标准库所需字段。
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
