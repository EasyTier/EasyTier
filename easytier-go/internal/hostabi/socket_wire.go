package hostabi

import (
	"encoding/binary"
	"fmt"
	"net"
	"unicode/utf8"

	"github.com/EasyTier/EasyTier/easytier-go/platform"
	"github.com/metacubex/wazero/api"
)

const (
	socketAddressLen      = 27
	tcpSocketResultLen    = 62
	boundSocketResultLen  = 35
	maxFactoryOptionsSize = 4096
)

func readOwnedOptions(module api.Module, pointer, length uint32) ([]byte, bool) {
	if length > maxFactoryOptionsSize {
		return nil, false
	}
	options, ok := module.Memory().Read(pointer, length)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), options...), true
}

func decodeTCPConnectOptions(encoded []byte) (platform.TCPConnectOptions, error) {
	if len(encoded) < 75 || encoded[0] != 2 {
		return platform.TCPConnectOptions{}, fmt.Errorf("invalid TCP connect options")
	}
	remote, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || remote == nil {
		return platform.TCPConnectOptions{}, fmt.Errorf("invalid TCP remote address")
	}
	local, err := decodeSocketAddress(encoded[28:55], true)
	if err != nil {
		return platform.TCPConnectOptions{}, err
	}
	socketContext, remainder, err := decodeSocketContext(encoded[55:])
	if err != nil {
		return platform.TCPConnectOptions{}, fmt.Errorf("invalid TCP socket context: %w", err)
	}
	if len(remainder) < 9 {
		return platform.TCPConnectOptions{}, fmt.Errorf("truncated TCP bind policy")
	}
	bind, err := decodeTCPBindPolicy(
		udpToTCPAddr(local),
		socketContext,
		remainder[0],
		remainder[1],
		remainder[2],
		remainder[4:],
	)
	if err != nil {
		return platform.TCPConnectOptions{}, err
	}
	purpose, err := decodeTCPConnectPurpose(remainder[3])
	if err != nil {
		return platform.TCPConnectOptions{}, err
	}
	return platform.TCPConnectOptions{
		RemoteAddr: &net.TCPAddr{IP: remote.IP, Port: remote.Port, Zone: remote.Zone},
		Bind:       bind,
		Purpose:    purpose,
	}, nil
}

func decodeUDPBindOptions(encoded []byte) (platform.UDPBindOptions, error) {
	if len(encoded) < 48 || encoded[0] != 2 {
		return platform.UDPBindOptions{}, fmt.Errorf("invalid UDP bind options")
	}
	local, err := decodeSocketAddress(encoded[1:28], true)
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	socketContext, remainder, err := decodeSocketContext(encoded[28:])
	if err != nil {
		return platform.UDPBindOptions{}, fmt.Errorf("invalid UDP socket context: %w", err)
	}
	if len(remainder) < 9 {
		return platform.UDPBindOptions{}, fmt.Errorf("truncated UDP bind policy")
	}
	reuseAddr, err := decodeWireBool("UDP reuse_addr", remainder[0])
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	reusePort, err := decodeWireBool("UDP reuse_port", remainder[1])
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	onlyV6, err := decodeWireBool("UDP only_v6", remainder[2])
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	purpose, err := decodeUDPBindPurpose(remainder[3])
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	device, err := decodeBindDevice(remainder[4:])
	if err != nil {
		return platform.UDPBindOptions{}, err
	}
	return platform.UDPBindOptions{
		Context:    socketContext,
		LocalAddr:  local,
		BindDevice: device,
		ReuseAddr:  reuseAddr,
		ReusePort:  reusePort,
		OnlyV6:     onlyV6,
		Purpose:    purpose,
	}, nil
}

func decodeTCPListenOptions(encoded []byte) (platform.TCPListenOptions, error) {
	if len(encoded) < 48 || encoded[0] != 2 {
		return platform.TCPListenOptions{}, fmt.Errorf("invalid TCP listen options")
	}
	local, err := decodeSocketAddress(encoded[1:28], false)
	if err != nil || local == nil {
		return platform.TCPListenOptions{}, fmt.Errorf("invalid TCP listen address")
	}
	socketContext, remainder, err := decodeSocketContext(encoded[28:])
	if err != nil {
		return platform.TCPListenOptions{}, fmt.Errorf("invalid TCP listen context: %w", err)
	}
	if len(remainder) < 9 {
		return platform.TCPListenOptions{}, fmt.Errorf("truncated TCP listen bind policy")
	}
	bind, err := decodeTCPBindPolicy(
		&net.TCPAddr{IP: local.IP, Port: local.Port, Zone: local.Zone},
		socketContext,
		remainder[0],
		remainder[1],
		remainder[2],
		remainder[4:],
	)
	if err != nil {
		return platform.TCPListenOptions{}, err
	}
	purpose, err := decodeTCPListenPurpose(remainder[3])
	if err != nil {
		return platform.TCPListenOptions{}, err
	}
	return platform.TCPListenOptions{Bind: bind, Purpose: purpose}, nil
}

func decodeTCPBindPolicy(
	localAddr *net.TCPAddr,
	socketContext platform.SocketContext,
	reuseMode byte,
	reusePortByte byte,
	onlyV6Byte byte,
	deviceBytes []byte,
) (platform.TCPBindOptions, error) {
	var reuseAddr *bool
	switch reuseMode {
	case 0:
	case 1:
		value := false
		reuseAddr = &value
	case 2:
		value := true
		reuseAddr = &value
	default:
		return platform.TCPBindOptions{}, fmt.Errorf("invalid TCP reuse_addr")
	}
	reusePort, err := decodeWireBool("TCP reuse_port", reusePortByte)
	if err != nil {
		return platform.TCPBindOptions{}, err
	}
	onlyV6, err := decodeWireBool("TCP only_v6", onlyV6Byte)
	if err != nil {
		return platform.TCPBindOptions{}, err
	}
	device, err := decodeBindDevice(deviceBytes)
	if err != nil {
		return platform.TCPBindOptions{}, err
	}
	return platform.TCPBindOptions{
		Context:    socketContext,
		LocalAddr:  localAddr,
		BindDevice: device,
		ReuseAddr:  reuseAddr,
		ReusePort:  reusePort,
		OnlyV6:     onlyV6,
	}, nil
}

func decodeSocketContext(
	encoded []byte,
) (platform.SocketContext, []byte, error) {
	if len(encoded) < 11 {
		return platform.SocketContext{}, nil, fmt.Errorf("truncated socket context")
	}
	ipVersion, err := decodeIPVersion(encoded[0])
	if err != nil {
		return platform.SocketContext{}, nil, err
	}
	mark, err := decodeSocketMark(encoded[1], encoded[2:6])
	if err != nil {
		return platform.SocketContext{}, nil, err
	}
	if encoded[6] > 1 {
		return platform.SocketContext{}, nil, fmt.Errorf("invalid netns presence")
	}
	length := int(binary.BigEndian.Uint32(encoded[7:11]))
	if length > len(encoded)-11 || (encoded[6] == 0 && length != 0) {
		return platform.SocketContext{}, nil, fmt.Errorf("invalid netns length")
	}
	var netns *string
	if encoded[6] == 1 {
		token := encoded[11 : 11+length]
		if !utf8.Valid(token) {
			return platform.SocketContext{}, nil, fmt.Errorf("netns token is not UTF-8")
		}
		value := string(token)
		netns = &value
	}
	return platform.SocketContext{
		IPVersion:  ipVersion,
		SocketMark: mark,
		NetNS:      netns,
	}, encoded[11+length:], nil
}

func decodeIPVersion(encoded byte) (platform.IPVersion, error) {
	switch encoded {
	case 0:
		return platform.IPVersionV4, nil
	case 1:
		return platform.IPVersionV6, nil
	case 2:
		return platform.IPVersionBoth, nil
	default:
		return 0, fmt.Errorf("invalid IP version %d", encoded)
	}
}

func decodeSocketMark(present byte, encoded []byte) (*uint32, error) {
	if present > 1 || len(encoded) != 4 ||
		(present == 0 && binary.BigEndian.Uint32(encoded) != 0) {
		return nil, fmt.Errorf("invalid socket mark encoding")
	}
	if present == 0 {
		return nil, nil
	}
	mark := binary.BigEndian.Uint32(encoded)
	return &mark, nil
}

func decodeWireBool(name string, encoded byte) (bool, error) {
	if encoded > 1 {
		return false, fmt.Errorf("invalid %s", name)
	}
	return encoded == 1, nil
}

func decodeBindDevice(encoded []byte) (*string, error) {
	if len(encoded) < 5 || encoded[0] > 1 {
		return nil, fmt.Errorf("invalid bind device encoding")
	}
	length := int(binary.BigEndian.Uint32(encoded[1:5]))
	if len(encoded) != 5+length || (encoded[0] == 0 && length != 0) {
		return nil, fmt.Errorf("invalid bind device length")
	}
	if encoded[0] == 0 {
		return nil, nil
	}
	device := string(encoded[5:])
	return &device, nil
}

func decodeSocketAddress(encoded []byte, optional bool) (*net.UDPAddr, error) {
	if len(encoded) != socketAddressLen {
		return nil, fmt.Errorf("invalid socket address length")
	}
	if optional && encoded[0] == 0 {
		for _, value := range encoded[1:] {
			if value != 0 {
				return nil, fmt.Errorf("noncanonical absent socket address")
			}
		}
		return nil, nil
	}
	metadata := make([]byte, udpMetadataLen)
	copy(metadata, encoded)
	address, _, flowinfo, _, err := decodeUDPMetadata(metadata)
	if err == nil && flowinfo != 0 {
		return nil, fmt.Errorf("IPv6 flowinfo is not supported")
	}
	return address, err
}

func udpToTCPAddr(address *net.UDPAddr) *net.TCPAddr {
	if address == nil {
		return nil
	}
	return &net.TCPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
}

func encodeTCPSocketResult(
	handle uint64,
	localAddr net.Addr,
	peerAddr net.Addr,
) ([tcpSocketResultLen]byte, error) {
	var encoded [tcpSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	peer, err := encodeNetAddr(peerAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:35], local[:])
	copy(encoded[35:], peer[:])
	return encoded, nil
}

func encodeBoundSocketResult(
	handle uint64,
	localAddr net.Addr,
) ([boundSocketResultLen]byte, error) {
	var encoded [boundSocketResultLen]byte
	binary.BigEndian.PutUint64(encoded[:8], handle)
	local, err := encodeNetAddr(localAddr)
	if err != nil {
		return encoded, err
	}
	copy(encoded[8:], local[:])
	return encoded, nil
}

func encodeNetAddr(address net.Addr) ([socketAddressLen]byte, error) {
	var encoded [socketAddressLen]byte
	var udpAddr *net.UDPAddr
	switch address := address.(type) {
	case *net.TCPAddr:
		udpAddr = &net.UDPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
	case *net.UDPAddr:
		udpAddr = address
	default:
		return encoded, fmt.Errorf("unsupported socket address %T", address)
	}
	metadata, err := encodeUDPMetadata(udpAddr, nil, 0)
	if err != nil {
		return encoded, err
	}
	copy(encoded[:], metadata[:socketAddressLen])
	return encoded, nil
}

func decodeTCPConnectPurpose(encoded byte) (platform.TCPConnectPurpose, error) {
	switch encoded {
	case 0:
		return platform.TCPConnectDirect, nil
	case 1:
		return platform.TCPConnectFake, nil
	case 2:
		return platform.TCPConnectHolePunch, nil
	case 3:
		return platform.TCPConnectManual, nil
	case 4:
		return platform.TCPConnectProxyNAT, nil
	case 5:
		return platform.TCPConnectSTUNProbe, nil
	case 6:
		return platform.TCPConnectSocks5, nil
	case 7:
		return platform.TCPConnectPortForward, nil
	case 8:
		return platform.TCPConnectDataPlane, nil
	default:
		return 0, fmt.Errorf("invalid TCP connect purpose %d", encoded)
	}
}

func decodeUDPBindPurpose(encoded byte) (platform.UDPBindPurpose, error) {
	switch encoded {
	case 0:
		return platform.UDPBindHolePunchControl, nil
	case 1:
		return platform.UDPBindHolePunchCandidate, nil
	case 2:
		return platform.UDPBindDirect, nil
	case 3:
		return platform.UDPBindPortBoundListener, nil
	case 4:
		return platform.UDPBindProxyNAT, nil
	case 5:
		return platform.UDPBindSTUNProbe, nil
	case 6:
		return platform.UDPBindSocks5, nil
	case 7:
		return platform.UDPBindPortForward, nil
	case 8:
		return platform.UDPBindPortLease, nil
	default:
		return 0, fmt.Errorf("invalid UDP bind purpose %d", encoded)
	}
}

func decodeTCPListenPurpose(encoded byte) (platform.TCPListenPurpose, error) {
	switch encoded {
	case 0:
		return platform.TCPListenDirect, nil
	case 1:
		return platform.TCPListenHolePunch, nil
	case 2:
		return platform.TCPListenManual, nil
	case 3:
		return platform.TCPListenProxyNAT, nil
	case 4:
		return platform.TCPListenSocks5, nil
	case 5:
		return platform.TCPListenPortForward, nil
	case 6:
		return platform.TCPListenPortLease, nil
	default:
		return 0, fmt.Errorf("invalid TCP listen purpose %d", encoded)
	}
}
