package coreabi

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	socketAddressLength       = 27
	operationIDLength         = 8
	completionLength          = 12
	streamResultLength        = 8 + socketAddressLength*2
	bindResultLength          = 8 + socketAddressLength
	tcpReadMetadataLength     = 1
	udpReceiveMetadataLength  = socketAddressLength + 1
	maxDataPlaneTransferBytes = 1024 * 1024
)

func encodeSocketAddress(address netip.AddrPort) ([socketAddressLength]byte, error) {
	var wire [socketAddressLength]byte
	if !address.IsValid() || !address.Addr().Is4() {
		return wire, fmt.Errorf("data plane ABI v2 requires an IPv4 address")
	}
	wire[0] = 4
	ip := address.Addr().As4()
	copy(wire[1:5], ip[:])
	binary.BigEndian.PutUint16(wire[17:19], address.Port())
	return wire, nil
}

func decodeSocketAddress(wire []byte) (netip.AddrPort, error) {
	if len(wire) != socketAddressLength {
		return netip.AddrPort{}, fmt.Errorf(
			"decode socket address with length %d", len(wire),
		)
	}
	if wire[0] != 4 {
		return netip.AddrPort{}, fmt.Errorf(
			"data plane ABI v2 returned address family %d", wire[0],
		)
	}
	for _, value := range wire[5:17] {
		if value != 0 {
			return netip.AddrPort{}, fmt.Errorf(
				"data plane ABI returned noncanonical IPv4 padding",
			)
		}
	}
	for _, value := range wire[19:27] {
		if value != 0 {
			return netip.AddrPort{}, fmt.Errorf(
				"data plane ABI returned IPv4 flow or scope metadata",
			)
		}
	}
	address := netip.AddrFrom4([4]byte(wire[1:5]))
	return netip.AddrPortFrom(address, binary.BigEndian.Uint16(wire[17:19])), nil
}

func decodeCompletions(wire []byte) ([]Completion, error) {
	if len(wire)%completionLength != 0 {
		return nil, fmt.Errorf("decode completion bytes with length %d", len(wire))
	}
	completions := make([]Completion, 0, len(wire)/completionLength)
	for len(wire) != 0 {
		operation := OperationID(binary.BigEndian.Uint64(wire[:8]))
		kind := OperationKind(binary.BigEndian.Uint16(wire[8:10]))
		status := ErrorKind(binary.BigEndian.Uint16(wire[10:12]))
		if operation == 0 {
			return nil, fmt.Errorf("data plane returned zero operation ID")
		}
		if !kind.valid() {
			return nil, fmt.Errorf("data plane returned operation kind %d", kind)
		}
		if !status.validCompletionStatus() {
			return nil, fmt.Errorf("data plane returned completion status %d", status)
		}
		completions = append(completions, Completion{
			Operation: operation,
			Kind:      kind,
			Status:    status,
		})
		wire = wire[completionLength:]
	}
	return completions, nil
}

func decodeStreamResult(wire []byte) (ResourceID, netip.AddrPort, netip.AddrPort, error) {
	if len(wire) != streamResultLength {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf(
			"decode stream result with length %d", len(wire),
		)
	}
	resource := ResourceID(binary.BigEndian.Uint64(wire[:8]))
	if resource == 0 {
		return 0, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf(
			"data plane returned zero stream resource ID",
		)
	}
	local, err := decodeSocketAddress(wire[8 : 8+socketAddressLength])
	if err != nil {
		return 0, netip.AddrPort{}, netip.AddrPort{}, err
	}
	peer, err := decodeSocketAddress(wire[8+socketAddressLength:])
	if err != nil {
		return 0, netip.AddrPort{}, netip.AddrPort{}, err
	}
	return resource, local, peer, nil
}

func decodeBindResult(wire []byte) (ResourceID, netip.AddrPort, error) {
	if len(wire) != bindResultLength {
		return 0, netip.AddrPort{}, fmt.Errorf(
			"decode bind result with length %d", len(wire),
		)
	}
	resource := ResourceID(binary.BigEndian.Uint64(wire[:8]))
	if resource == 0 {
		return 0, netip.AddrPort{}, fmt.Errorf(
			"data plane returned zero bound resource ID",
		)
	}
	address, err := decodeSocketAddress(wire[8:])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return resource, address, nil
}
