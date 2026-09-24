package hostabi

import (
	"encoding/binary"
	"errors"
	"net"
)

const udpMetadataLen = 48

func encodeUDPMetadata(
	peer *net.UDPAddr,
	optionalIP net.IP,
	optionalIfindex uint32,
) ([udpMetadataLen]byte, error) {
	var metadata [udpMetadataLen]byte
	if peer == nil {
		return metadata, errors.New("nil UDP peer")
	}
	if ipv4 := peer.IP.To4(); ipv4 != nil {
		metadata[0] = 4
		copy(metadata[1:5], ipv4)
	} else if ipv6 := peer.IP.To16(); ipv6 != nil {
		metadata[0] = 6
		copy(metadata[1:17], ipv6)
		if peer.Zone != "" {
			iface, err := net.InterfaceByName(peer.Zone)
			if err != nil {
				return metadata, err
			}
			binary.BigEndian.PutUint32(metadata[23:27], uint32(iface.Index))
		}
	} else {
		return metadata, errors.New("invalid UDP peer IP")
	}
	if peer.Port < 0 || peer.Port > 65535 {
		return metadata, errors.New("invalid UDP peer port")
	}
	binary.BigEndian.PutUint16(metadata[17:19], uint16(peer.Port))

	if optionalIP == nil {
		if optionalIfindex != 0 {
			return metadata, errors.New("optional UDP interface index requires an IP")
		}
		return metadata, nil
	}
	if ipv4 := optionalIP.To4(); ipv4 != nil {
		if optionalIfindex != 0 {
			return metadata, errors.New("optional IPv4 cannot carry an interface index")
		}
		metadata[27] = 4
		copy(metadata[28:32], ipv4)
		return metadata, nil
	}
	if ipv6 := optionalIP.To16(); ipv6 != nil {
		metadata[27] = 6
		copy(metadata[28:44], ipv6)
		binary.BigEndian.PutUint32(metadata[44:48], optionalIfindex)
		return metadata, nil
	}
	return metadata, errors.New("invalid optional UDP IP")
}

func decodeUDPMetadata(metadata []byte) (*net.UDPAddr, net.IP, uint32, uint32, error) {
	if len(metadata) != udpMetadataLen {
		return nil, nil, 0, 0, errors.New("invalid UDP metadata length")
	}
	var peerIP net.IP
	switch metadata[0] {
	case 4:
		if !allZero(metadata[5:17]) || !allZero(metadata[19:27]) {
			return nil, nil, 0, 0, errors.New("noncanonical IPv4 peer metadata")
		}
		peerIP = net.IPv4(metadata[1], metadata[2], metadata[3], metadata[4])
	case 6:
		peerIP = append(net.IP(nil), metadata[1:17]...)
	default:
		return nil, nil, 0, 0, errors.New("invalid UDP peer family")
	}
	flowinfo := binary.BigEndian.Uint32(metadata[19:23])
	scopeID := binary.BigEndian.Uint32(metadata[23:27])
	zone := ""
	if scopeID != 0 {
		iface, err := net.InterfaceByIndex(int(scopeID))
		if err != nil {
			return nil, nil, 0, 0, err
		}
		zone = iface.Name
	}
	peer := &net.UDPAddr{
		IP:   peerIP,
		Port: int(binary.BigEndian.Uint16(metadata[17:19])),
		Zone: zone,
	}

	var optionalIP net.IP
	switch metadata[27] {
	case 0:
		if !allZero(metadata[28:48]) {
			return nil, nil, 0, 0, errors.New("noncanonical absent optional IP")
		}
	case 4:
		if !allZero(metadata[32:48]) {
			return nil, nil, 0, 0, errors.New("noncanonical optional IPv4")
		}
		optionalIP = net.IPv4(metadata[28], metadata[29], metadata[30], metadata[31])
	case 6:
		optionalIP = append(net.IP(nil), metadata[28:44]...)
	default:
		return nil, nil, 0, 0, errors.New("invalid optional UDP IP family")
	}
	return peer, optionalIP, flowinfo, binary.BigEndian.Uint32(metadata[44:48]), nil
}

func allZero(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}
