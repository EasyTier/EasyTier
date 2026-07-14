package host

import (
	"context"
	"net"
	"net/netip"
	"sync"
)

type opaqueReadOperation struct {
	handle uint64
	done   bool
	data   []byte
	err    error
}

type opaqueWriteOperation struct {
	done bool
	err  error
}

type opaqueUDPDatagram struct {
	data []byte
	peer *net.UDPAddr
}

type opaqueUDPSend struct {
	data []byte
	peer *net.UDPAddr
}

type opaqueUDPReadWaiter struct {
	handle uint64
	ready  bool
}

type opaqueUDPWriteWaiter struct {
	handle uint64
	ready  bool
}

type opaquePacketState struct {
	connection     net.PacketConn
	received       []opaqueUDPDatagram
	receiveRunning bool
	receiveErr     error
	sendQueue      chan opaqueUDPSend
	sendErr        error
	closeOnce      sync.Once
}

type opaqueTCPListenerState struct {
	listener      net.Listener
	accepted      []net.Conn
	acceptRunning bool
	acceptErr     error
}

type opaqueTCPAcceptWaiter struct {
	handle uint64
	ready  bool
}

type opaqueCreateOperation struct {
	done       bool
	cancel     context.CancelFunc
	connection net.Conn
	packet     net.PacketConn
	listener   net.Listener
	localAddr  net.Addr
	peerAddr   net.Addr
	err        error
}

type DNSResolver interface {
	LookupIP(context.Context, DNSQuery) ([]netip.Addr, error)
	// LookupTXT returns one host-normalized core TXT value. Implementations
	// preserve their intended RR/chunk and UTF-8 policy before this seam.
	LookupTXT(context.Context, DNSQuery) (string, error)
	LookupSRV(context.Context, DNSQuery) ([]*net.SRV, error)
}

type opaqueDNSOperation struct {
	cancel context.CancelFunc
	done   bool
	result []byte
	err    error
}

type opaqueDNSKind uint8

type ConnectorEnvironment interface {
	LocalAddrForRemote(context.Context, *net.UDPAddr) (net.Addr, error)
}

type opaqueEnvironmentOperation struct {
	cancel  context.CancelFunc
	done    bool
	address net.Addr
	err     error
}

type opaquePacketSinkState struct {
	capacity int
	packets  [][]byte
}

type opaquePacketWriteWaiter struct {
	handle uint64
	ready  bool
}

type bridgeState struct {
	mu                  sync.Mutex
	closed              bool
	coreModuleBound     bool
	closeDone           chan struct{}
	handles             map[uint64]net.Conn
	packets             map[uint64]*opaquePacketState
	listeners           map[uint64]*opaqueTCPListenerState
	reads               map[uint64]*opaqueReadOperation
	writes              map[uint64]*opaqueWriteOperation
	udpReads            map[uint64]*opaqueUDPReadWaiter
	udpWrites           map[uint64]*opaqueUDPWriteWaiter
	tcpAccepts          map[uint64]*opaqueTCPAcceptWaiter
	creates             map[uint64]*opaqueCreateOperation
	dns                 map[uint64]*opaqueDNSOperation
	dnsResolver         DNSResolver
	socketFactory       SocketFactory
	environment         map[uint64]*opaqueEnvironmentOperation
	environmentResolver ConnectorEnvironment
	packetSinks         map[uint64]*opaquePacketSinkState
	packetWrites        map[uint64]*opaquePacketWriteWaiter
	environmentCalls    int
	nextHandle          uint64
	completion          chan struct{}
	workers             sync.WaitGroup
}

// Bridge owns the host resources and completion domain used by one core
// module. Copies share the same private state.
type Bridge struct {
	*bridgeState
}

type opaqueBridge = Bridge

func (b *opaqueBridge) allocateHandleLocked() uint64 {
	b.nextHandle++
	return b.nextHandle
}
