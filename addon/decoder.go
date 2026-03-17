package addon

import "github.com/DontBeProud/go-mitmproxy/proxy"

// decode content-encoding then respond to client

type Decoder struct {
	proxy.BaseAddon
}

func (d *Decoder) Response(f *proxy.Flow) {
	f.Response.ReplaceToDecodedBody()
}
