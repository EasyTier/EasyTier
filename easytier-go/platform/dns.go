package platform

import (
	"context"
	"net"
	"net/netip"
)

type DNSQuery struct {
	Host       string
	IPVersion  uint8
	SocketMark *uint32
	NetNS      *string
}

type DNSResolver interface {
	LookupIP(context.Context, DNSQuery) ([]netip.Addr, error)
	LookupTXT(context.Context, DNSQuery) (string, error)
	LookupSRV(context.Context, DNSQuery) ([]*net.SRV, error)
}
