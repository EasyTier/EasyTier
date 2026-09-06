package reactor

import "fmt"

type eventSink func(kind, message string) bool

func (reactor *Reactor) RegisterEventSink(deliver eventSink) (uint64, error) {
	if deliver == nil {
		return 0, fmt.Errorf("event sink delivery function must not be nil")
	}
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	if reactor.closed {
		return 0, ErrInvalid
	}
	handle := reactor.allocateHandleLocked()
	reactor.eventSinks[handle] = deliver
	return handle, nil
}

func (reactor *Reactor) UnregisterEventSink(handle uint64) {
	reactor.mu.Lock()
	delete(reactor.eventSinks, handle)
	reactor.mu.Unlock()
}

func (reactor *Reactor) TryEventWrite(handle uint64, kind, message string) error {
	reactor.mu.Lock()
	defer reactor.mu.Unlock()
	deliver, exists := reactor.eventSinks[handle]
	if !exists {
		return ErrInvalid
	}
	if !deliver(kind, message) {
		return ErrWouldBlock
	}
	return nil
}
