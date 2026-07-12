package host

// Opaque UDP sessions remain host-owned while core drives their operations.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/tetratelabs/wazero/api"
)

const (
	opaqueHostWouldBlock = -5
	udpMetadataLen       = 48
)

func newOpaquePacketState(connection net.PacketConn) *opaquePacketState {
	return &opaquePacketState{
		connection: connection,
		sendQueue:  make(chan opaqueUDPSend, 1),
	}
}

func (s *opaquePacketState) closeAfterQueuedSends() {
	s.closeOnce.Do(func() { close(s.sendQueue) })
}

func (b *opaqueBridge) runUDPSends(handle uint64, state *opaquePacketState) {
	defer b.workers.Done()
	defer state.connection.Close()

	for request := range state.sendQueue {
		b.mu.Lock()
		for _, waiter := range b.udpWrites {
			if waiter.handle == handle {
				waiter.ready = true
			}
		}
		b.mu.Unlock()
		b.signalCompletion()

		n, err := state.connection.WriteTo(request.data, request.peer)
		if err == nil && n != len(request.data) {
			err = fmt.Errorf("short UDP write: %d of %d", n, len(request.data))
		}
		if err != nil {
			b.mu.Lock()
			state.sendErr = err
			for _, waiter := range b.udpWrites {
				if waiter.handle == handle {
					waiter.ready = true
				}
			}
			b.mu.Unlock()
			b.signalCompletion()
		}
	}
}

func (b *opaqueBridge) startUDPRecv(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
	_ uint32,
) int32 {
	b.mu.Lock()
	state, exists := b.packets[handle]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if _, duplicate := b.udpReads[operation]; duplicate {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	waiter := &opaqueUDPReadWaiter{handle: handle}
	waiter.ready = len(state.received) > 0 || state.receiveErr != nil
	b.udpReads[operation] = waiter
	startWorker := !waiter.ready && !state.receiveRunning
	if startWorker {
		state.receiveRunning = true
		b.workers.Add(1)
	}
	b.mu.Unlock()

	if startWorker {
		go b.runUDPReceive(handle, state)
	}
	if waiter.ready {
		b.signalCompletion()
	}
	return 0
}

func (b *opaqueBridge) runUDPReceive(handle uint64, state *opaquePacketState) {
	defer b.workers.Done()

	buffer := make([]byte, 65535)
	n, peer, err := state.connection.ReadFrom(buffer)
	var udpPeer *net.UDPAddr
	if err == nil {
		var ok bool
		udpPeer, ok = peer.(*net.UDPAddr)
		if !ok {
			err = fmt.Errorf("unsupported UDP peer address %T", peer)
		}
	}

	b.mu.Lock()
	state.receiveRunning = false
	if err != nil {
		state.receiveErr = err
	} else {
		state.received = append(state.received, opaqueUDPDatagram{
			data: append([]byte(nil), buffer[:n]...),
			peer: cloneUDPAddr(udpPeer),
		})
	}
	for _, waiter := range b.udpReads {
		if waiter.handle == handle {
			waiter.ready = true
		}
	}
	b.mu.Unlock()
	b.signalCompletion()
}

func (b *opaqueBridge) takeUDPRecv(
	_ context.Context,
	module api.Module,
	operation uint64,
	destination uint32,
	capacity uint32,
	metadataDestination uint32,
	metadataLength uint32,
) int32 {
	if metadataLength != udpMetadataLen {
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(destination, capacity); !ok {
		return opaqueHostMemory
	}
	if _, ok := module.Memory().Read(metadataDestination, metadataLength); !ok {
		return opaqueHostMemory
	}

	b.mu.Lock()
	waiter, exists := b.udpReads[operation]
	if !exists {
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	state, exists := b.packets[waiter.handle]
	if !exists {
		delete(b.udpReads, operation)
		b.mu.Unlock()
		return opaqueHostInvalid
	}
	if len(state.received) == 0 {
		if state.receiveErr == nil {
			b.mu.Unlock()
			return opaqueHostPending
		}
		delete(b.udpReads, operation)
		b.mu.Unlock()
		return opaqueHostIOError
	}
	datagram := state.received[0]
	state.received = state.received[1:]
	delete(b.udpReads, operation)
	startWorker := len(state.received) == 0 && !state.receiveRunning && hasUDPReadWaiter(b, waiter.handle)
	if startWorker {
		state.receiveRunning = true
		b.workers.Add(1)
	}
	b.mu.Unlock()

	if startWorker {
		go b.runUDPReceive(waiter.handle, state)
	}
	length := min(len(datagram.data), int(capacity))
	if length > 0 && !module.Memory().Write(destination, datagram.data[:length]) {
		return opaqueHostMemory
	}
	metadata, err := encodeUDPMetadata(datagram.peer, nil, 0)
	if err != nil {
		return opaqueHostInvalid
	}
	if !module.Memory().Write(metadataDestination, metadata[:]) {
		return opaqueHostMemory
	}
	return int32(length)
}

func (b *opaqueBridge) tryUDPSend(
	_ context.Context,
	module api.Module,
	handle uint64,
	source uint32,
	length uint32,
	metadataSource uint32,
	metadataLength uint32,
) int32 {
	if metadataLength != udpMetadataLen || length > 65535 {
		return opaqueHostMemory
	}
	metadata, ok := module.Memory().Read(metadataSource, metadataLength)
	if !ok {
		return opaqueHostMemory
	}
	peer, sourceIP, flowinfo, sourceIfindex, err := decodeUDPMetadata(metadata)
	if err != nil || sourceIP != nil || flowinfo != 0 || sourceIfindex != 0 {
		return opaqueHostInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state, exists := b.packets[handle]
	if !exists {
		return opaqueHostInvalid
	}
	if state.sendErr != nil {
		return opaqueHostIOError
	}
	if len(state.sendQueue) >= cap(state.sendQueue) {
		return opaqueHostWouldBlock
	}
	data, ok := module.Memory().Read(source, length)
	if !ok {
		return opaqueHostMemory
	}
	state.sendQueue <- opaqueUDPSend{
		data: append([]byte(nil), data...),
		peer: peer,
	}
	return 0
}

func (b *opaqueBridge) startUDPSendReady(
	_ context.Context,
	_ api.Module,
	handle uint64,
	operation uint64,
) int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, exists := b.packets[handle]
	if !exists {
		return opaqueHostInvalid
	}
	if _, duplicate := b.udpWrites[operation]; duplicate {
		return opaqueHostInvalid
	}
	waiter := &opaqueUDPWriteWaiter{
		handle: handle,
		ready:  len(state.sendQueue) < cap(state.sendQueue) || state.sendErr != nil,
	}
	b.udpWrites[operation] = waiter
	if waiter.ready {
		b.signalCompletion()
	}
	return 0
}

func (b *opaqueBridge) takeUDPSendReady(
	_ context.Context,
	_ api.Module,
	operation uint64,
) int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	waiter, exists := b.udpWrites[operation]
	if !exists {
		return opaqueHostInvalid
	}
	if !waiter.ready {
		return opaqueHostPending
	}
	delete(b.udpWrites, operation)
	state, exists := b.packets[waiter.handle]
	if !exists {
		return opaqueHostInvalid
	}
	if state.sendErr != nil {
		return opaqueHostIOError
	}
	return 0
}

func hasUDPReadWaiter(b *opaqueBridge, handle uint64) bool {
	for _, waiter := range b.udpReads {
		if waiter.handle == handle {
			return true
		}
	}
	return false
}

func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func encodeUDPMetadata(
	peer *net.UDPAddr,
	optionalIP net.IP,
	optionalIfindex uint32,
) ([udpMetadataLen]byte, error) {
	var metadata [udpMetadataLen]byte
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

func allZero(bytes []byte) bool {
	for _, value := range bytes {
		if value != 0 {
			return false
		}
	}
	return true
}
