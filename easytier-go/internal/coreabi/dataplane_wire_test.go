package coreabi

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestSocketAddressWireMatchesEasyTierABI(t *testing.T) {
	address := netip.MustParseAddrPort("192.0.2.1:11013")
	wire, err := encodeSocketAddress(address)
	if err != nil {
		t.Fatalf("encode address: %v", err)
	}
	want := [socketAddressLength]byte{
		4, 192, 0, 2, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x2b, 0x05,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	if wire != want {
		t.Fatalf("encoded address = %v, want %v", wire, want)
	}
	decoded, err := decodeSocketAddress(wire[:])
	if err != nil {
		t.Fatalf("decode address: %v", err)
	}
	if decoded != address {
		t.Fatalf("decoded address = %v, want %v", decoded, address)
	}
}

func TestSocketAddressWireRejectsIPv6AndNoncanonicalIPv4(t *testing.T) {
	if _, err := encodeSocketAddress(
		netip.MustParseAddrPort("[2001:db8::1]:80"),
	); err == nil {
		t.Fatal("encode IPv6 address succeeded")
	}
	wire, err := encodeSocketAddress(netip.MustParseAddrPort("192.0.2.1:80"))
	if err != nil {
		t.Fatalf("encode IPv4 address: %v", err)
	}
	wire[5] = 1
	if _, err := decodeSocketAddress(wire[:]); err == nil {
		t.Fatal("decode noncanonical IPv4 address succeeded")
	}
}

func TestCompletionWireMatchesEasyTierABI(t *testing.T) {
	wire := make([]byte, completionLength*2)
	binary.BigEndian.PutUint64(wire[:8], 0x0102_0304_0506_0708)
	binary.BigEndian.PutUint16(wire[8:10], uint16(OperationUDPReceive))
	binary.BigEndian.PutUint16(wire[10:12], uint16(ErrorBufferTooSmall))
	binary.BigEndian.PutUint64(wire[12:20], 9)
	binary.BigEndian.PutUint16(wire[20:22], uint16(OperationTCPWrite))
	completions, err := decodeCompletions(wire)
	if err != nil {
		t.Fatalf("decode completions: %v", err)
	}
	want := []Completion{
		{
			Operation: 0x0102_0304_0506_0708,
			Kind:      OperationUDPReceive,
			Status:    ErrorBufferTooSmall,
		},
		{Operation: 9, Kind: OperationTCPWrite, Status: ErrorNone},
	}
	if !reflect.DeepEqual(completions, want) {
		t.Fatalf("completions = %#v, want %#v", completions, want)
	}
}
