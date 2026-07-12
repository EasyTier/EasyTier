package host

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unicode/utf8"
)

const (
	dnsWireVersion  = 1
	maxDNSResultLen = 1024 * 1024
)

type DNSQuery struct {
	Host       string
	IPVersion  uint8
	SocketMark *uint32
	NetNS      *string
}

func decodeDNSQuery(encoded []byte) (DNSQuery, error) {
	if len(encoded) < 16 || encoded[0] != dnsWireVersion {
		return DNSQuery{}, fmt.Errorf("invalid DNS query header")
	}
	query := DNSQuery{IPVersion: encoded[1]}
	if query.IPVersion != 0 && query.IPVersion != 4 && query.IPVersion != 6 {
		return DNSQuery{}, fmt.Errorf("invalid DNS IP version")
	}
	if encoded[2] > 1 {
		return DNSQuery{}, fmt.Errorf("invalid DNS socket mark presence")
	}
	if encoded[2] == 1 {
		mark := binary.BigEndian.Uint32(encoded[3:7])
		query.SocketMark = &mark
	} else if binary.BigEndian.Uint32(encoded[3:7]) != 0 {
		return DNSQuery{}, fmt.Errorf("DNS socket mark value without presence")
	}
	if encoded[7] > 1 {
		return DNSQuery{}, fmt.Errorf("invalid DNS netns presence")
	}
	offset := 12
	netnsLengthWire := binary.BigEndian.Uint32(encoded[8:12])
	if uint64(netnsLengthWire) > uint64(len(encoded)-offset) {
		return DNSQuery{}, fmt.Errorf("truncated DNS netns token")
	}
	netnsLength := int(netnsLengthWire)
	if encoded[7] == 0 && netnsLength != 0 {
		return DNSQuery{}, fmt.Errorf("DNS netns length without presence")
	}
	if encoded[7] == 1 {
		netnsBytes := encoded[offset : offset+netnsLength]
		if !utf8.Valid(netnsBytes) {
			return DNSQuery{}, fmt.Errorf("DNS netns token is not UTF-8")
		}
		netns := string(netnsBytes)
		query.NetNS = &netns
	}
	offset += netnsLength
	if len(encoded)-offset < 4 {
		return DNSQuery{}, fmt.Errorf("missing DNS host length")
	}
	hostLengthWire := binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	if hostLengthWire == 0 || uint64(hostLengthWire) != uint64(len(encoded)-offset) {
		return DNSQuery{}, fmt.Errorf("invalid DNS host length")
	}
	host := encoded[offset:]
	if !utf8.Valid(host) {
		return DNSQuery{}, fmt.Errorf("DNS host is not UTF-8")
	}
	query.Host = string(host)
	return query, nil
}

func encodeDNSAddresses(addresses []netip.Addr) ([]byte, error) {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(len(addresses)))
	for _, address := range addresses {
		if address.Is4() {
			ipv4 := address.As4()
			result = append(result, 4)
			result = append(result, ipv4[:]...)
			continue
		}
		if !address.Is6() {
			return nil, fmt.Errorf("invalid DNS address")
		}
		ipv6 := address.As16()
		result = append(result, 6)
		result = append(result, ipv6[:]...)
	}
	return boundedDNSResult(result)
}

func encodeDNSTXT(text string) ([]byte, error) {
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("normalized DNS TXT value is not UTF-8")
	}
	result := make([]byte, 4, 4+len(text))
	binary.BigEndian.PutUint32(result, uint32(len(text)))
	result = append(result, text...)
	return boundedDNSResult(result)
}

func encodeDNSSRV(records []*net.SRV) ([]byte, error) {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(len(records)))
	for _, record := range records {
		if record == nil {
			return nil, fmt.Errorf("nil DNS SRV record")
		}
		target := []byte(record.Target)
		result = binary.BigEndian.AppendUint16(result, record.Priority)
		result = binary.BigEndian.AppendUint16(result, record.Weight)
		result = binary.BigEndian.AppendUint16(result, record.Port)
		result = binary.BigEndian.AppendUint32(result, uint32(len(target)))
		result = append(result, target...)
	}
	return boundedDNSResult(result)
}

func boundedDNSResult(result []byte) ([]byte, error) {
	if len(result) == 0 || len(result) > maxDNSResultLen {
		return nil, fmt.Errorf("DNS result exceeds bridge limit")
	}
	return result, nil
}
