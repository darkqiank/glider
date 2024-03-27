package ssr

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/pkg/socks"
	"github.com/nadoo/glider/proxy"

	"github.com/nadoo/glider/proxy/ssr/internal"
	"github.com/nadoo/glider/proxy/ssr/internal/cipher"
	"github.com/nadoo/glider/proxy/ssr/internal/obfs"
	"github.com/nadoo/glider/proxy/ssr/internal/protocol"
	ssrinfo "github.com/nadoo/glider/proxy/ssr/internal/ssr"
)

func init() {
	proxy.RegisterDialer("ssr", NewSSRDialer)
}

// SSR struct.
type SSR struct {
	dialer proxy.Dialer
	addr   string

	EncryptMethod   string
	EncryptPassword string
	Obfs            string
	ObfsParam       string
	ObfsData        any
	Protocol        string
	ProtocolParam   string
	ProtocolData    any
}

// NewSSR returns a shadowsocksr proxy, ssr://method:pass@host:port/query
func NewSSR(s string, d proxy.Dialer) (*SSR, error) {
	var ss string

	// hh := s[0:6]
	bb := s[6:]
	newStr, err0 := base64.StdEncoding.DecodeString(bb)

	if err0 != nil {
		ss = s
		u, err := url.Parse(ss)
		if err != nil {
			log.F("[ssr] parse err, : %s", err)
			return nil, err
		}
		addr := u.Host
		method := u.User.Username()
		pass, _ := u.User.Password()

		p := &SSR{
			dialer:          d,
			addr:            addr,
			EncryptMethod:   method,
			EncryptPassword: pass,
		}

		query := u.Query()
		p.Protocol = query.Get("protocol")
		p.ProtocolParam = query.Get("protocol_param")
		p.Obfs = query.Get("obfs")
		p.ObfsParam = query.Get("obfs_param")

		p.ProtocolData = new(protocol.AuthData)

		return p, nil
	} else {
		// yd-05.paofunlink.com:1070:auth_aes128_sha1:chacha20-ietf:plain:YnhzbnVjcmdrNmhmaXNo/?obfsparam=MjJjYzQxOTI5ODkubWljcm9zb2Z0LmNvbQ&protoparam=MTkyOTg5OmNVa2FjNg&remarks=W3YxXSDlj7Dmub7jg7swMQ&group=5rOh6IqZ5LqR
		ss = string(newStr)
		// 分割主要部分和查询字符串
		parts := strings.Split(ss, "/?")
		mainParts := strings.Split(parts[0], ":")
		query := ""
		if len(parts) > 1 {
			query = parts[1]
		}
		if len(mainParts) < 6 {
			return nil, fmt.Errorf("invalid SSR link format")
		}
		// 解析查询字符串
		values, err := url.ParseQuery(query)
		if err != nil {
			return nil, fmt.Errorf("error parsing query params: %v", err)
		}
		// 解码ObfsParam和ProtocolParam（如果它们是Base64编码的）
		obfsParam, _ := base64.StdEncoding.DecodeString(values.Get("obfsparam"))
		protocolParam, _ := base64.StdEncoding.DecodeString(values.Get("protoparam"))
		password, _ := base64.StdEncoding.DecodeString(mainParts[5])

		p := &SSR{
			addr:            fmt.Sprintf("%s:%s", mainParts[0], mainParts[1]),
			EncryptMethod:   mainParts[3],
			EncryptPassword: string(password),
			Obfs:            mainParts[4],
			ObfsParam:       string(obfsParam),
			Protocol:        mainParts[2],
			ProtocolParam:   string(protocolParam),
		}
		p.ProtocolData = new(protocol.AuthData)
		return p, nil
	}

}

// NewSSRDialer returns a ssr proxy dialer.
func NewSSRDialer(s string, d proxy.Dialer) (proxy.Dialer, error) {
	return NewSSR(s, d)
}

// Addr returns forwarder's address
func (s *SSR) Addr() string {
	if s.addr == "" {
		return s.dialer.Addr()
	}
	return s.addr
}

// Dial connects to the address addr on the network net via the proxy.
func (s *SSR) Dial(network, addr string) (net.Conn, error) {
	target := socks.ParseAddr(addr)
	if target == nil {
		return nil, errors.New("[ssr] unable to parse address: " + addr)
	}

	cipher, err := cipher.NewStreamCipher(s.EncryptMethod, s.EncryptPassword)
	if err != nil {
		return nil, err
	}

	c, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		log.F("[ssr] dial to %s error: %s", s.addr, err)
		return nil, err
	}

	ssrconn := internal.NewSSTCPConn(c, cipher)
	if ssrconn.Conn == nil || ssrconn.RemoteAddr() == nil {
		return nil, errors.New("[ssr] nil connection")
	}

	// should initialize obfs/protocol now
	rs := strings.Split(ssrconn.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])

	ssrconn.IObfs = obfs.NewObfs(s.Obfs)
	if ssrconn.IObfs == nil {
		return nil, errors.New("[ssr] unsupported obfs type: " + s.Obfs)
	}

	obfsServerInfo := &ssrinfo.ServerInfo{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ObfsParam,
	}
	ssrconn.IObfs.SetServerInfo(obfsServerInfo)

	ssrconn.IProtocol = protocol.NewProtocol(s.Protocol)
	if ssrconn.IProtocol == nil {
		return nil, errors.New("[ssr] unsupported protocol type: " + s.Protocol)
	}

	protocolServerInfo := &ssrinfo.ServerInfo{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  s.ProtocolParam,
	}
	ssrconn.IProtocol.SetServerInfo(protocolServerInfo)

	if s.ObfsData == nil {
		s.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(s.ObfsData)

	if s.ProtocolData == nil {
		s.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(s.ProtocolData)

	if _, err := ssrconn.Write(target); err != nil {
		ssrconn.Close()
		return nil, err
	}

	return ssrconn, err
}

// DialUDP connects to the given address via the proxy.
func (s *SSR) DialUDP(network, addr string) (net.PacketConn, error) {
	return nil, proxy.ErrNotSupported
}

func init() {
	proxy.AddUsage("ssr", `
SSR scheme:
  ssr://method:pass@host:port?protocol=xxx&protocol_param=yyy&obfs=zzz&obfs_param=xyz
`)
}
