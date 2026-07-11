package host

import (
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf8"
)

const (
	dnsWireVersion  = 1
	maxDNSResultLen = 1024 * 1024
)

type decodedDNSQuery struct {
	host       string
	ipVersion  uint8
	socketMark *uint32
	netns      *string
}

func decodeDNSQuery(encoded []byte) (decodedDNSQuery, error) {
	if len(encoded) < 16 || encoded[0] != dnsWireVersion {
		return decodedDNSQuery{}, fmt.Errorf("invalid DNS query header")
	}
	query := decodedDNSQuery{ipVersion: encoded[1]}
	if query.ipVersion != 0 && query.ipVersion != 4 && query.ipVersion != 6 {
		return decodedDNSQuery{}, fmt.Errorf("invalid DNS IP version")
	}
	if encoded[2] > 1 {
		return decodedDNSQuery{}, fmt.Errorf("invalid DNS socket mark presence")
	}
	if encoded[2] == 1 {
		mark := binary.BigEndian.Uint32(encoded[3:7])
		query.socketMark = &mark
	}
	if encoded[7] > 1 {
		return decodedDNSQuery{}, fmt.Errorf("invalid DNS netns presence")
	}
	offset := 12
	netnsLength := int(binary.BigEndian.Uint32(encoded[8:12]))
	if netnsLength > len(encoded)-offset {
		return decodedDNSQuery{}, fmt.Errorf("truncated DNS netns token")
	}
	if encoded[7] == 0 && netnsLength != 0 {
		return decodedDNSQuery{}, fmt.Errorf("DNS netns length without presence")
	}
	if encoded[7] == 1 {
		netnsBytes := encoded[offset : offset+netnsLength]
		if !utf8.Valid(netnsBytes) {
			return decodedDNSQuery{}, fmt.Errorf("DNS netns token is not UTF-8")
		}
		netns := string(netnsBytes)
		query.netns = &netns
	}
	offset += netnsLength
	if len(encoded)-offset < 4 {
		return decodedDNSQuery{}, fmt.Errorf("missing DNS host length")
	}
	hostLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if hostLength == 0 || hostLength != len(encoded)-offset {
		return decodedDNSQuery{}, fmt.Errorf("invalid DNS host length")
	}
	host := encoded[offset:]
	if !utf8.Valid(host) {
		return decodedDNSQuery{}, fmt.Errorf("DNS host is not UTF-8")
	}
	query.host = string(host)
	return query, nil
}

func encodeDNSAddresses(addresses []net.IP) ([]byte, error) {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(len(addresses)))
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			result = append(result, 4)
			result = append(result, ipv4...)
			continue
		}
		ipv6 := address.To16()
		if ipv6 == nil {
			return nil, fmt.Errorf("invalid DNS address")
		}
		result = append(result, 6)
		result = append(result, ipv6...)
	}
	return boundedDNSResult(result)
}

func encodeDNSTXT(records []string) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("DNS TXT query returned no records")
	}
	text := records[0]
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
