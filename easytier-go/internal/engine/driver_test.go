package engine

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/easytier-go/internal/coreabi"
)

type recordingCore struct {
	calls []string
}

func (*recordingCore) Start(context.Context) error { return nil }
func (*recordingCore) Stop(context.Context) error  { return nil }
func (core *recordingCore) Drive(context.Context) (coreabi.State, error) {
	core.calls = append(core.calls, "drive")
	return coreabi.StateRunning, nil
}
func (core *recordingCore) NotifyCompletions(context.Context) error {
	core.calls = append(core.calls, "notify")
	return nil
}
func (core *recordingCore) NextDeadline(context.Context) (int64, error) {
	core.calls = append(core.calls, "deadline")
	return math.MaxInt64, nil
}
func (core *recordingCore) SendPacket(context.Context, []byte) error {
	core.calls = append(core.calls, "send")
	return nil
}
func (*recordingCore) Drop(context.Context) error { return nil }

func TestCompletionNotifiesGuestBeforeDriving(t *testing.T) {
	core := &recordingCore{}
	instance := &Instance{
		host:    &Host{},
		ctx:     context.Background(),
		core:    core,
		running: make(chan struct{}),
		stopped: make(chan struct{}),
	}
	if _, err := instance.drive(true); err != nil {
		t.Fatalf("drive completion: %v", err)
	}
	want := []string{"notify", "drive", "deadline"}
	if !reflect.DeepEqual(core.calls, want) {
		t.Fatalf("completion call order = %v, want %v", core.calls, want)
	}
}

func TestPacketIngressBatchDrivesOnce(t *testing.T) {
	core := &recordingCore{}
	instance := &Instance{
		host:     &Host{},
		ctx:      context.Background(),
		core:     core,
		commands: make(chan command, maximumPacketIngressBatch),
		running:  make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	requests := make([]command, 3)
	for index := range requests {
		requests[index] = command{
			kind:     commandSendPacket,
			packet:   []byte{byte(index)},
			response: make(chan error, 1),
		}
		if index != 0 {
			instance.commands <- requests[index]
		}
	}

	if _, err := instance.handlePacketBatch(requests[0], math.MaxInt64); err != nil {
		t.Fatalf("handle packet batch: %v", err)
	}
	for index := range requests {
		if err := <-requests[index].response; err != nil {
			t.Fatalf("packet %d response: %v", index, err)
		}
	}
	want := []string{"send", "send", "send", "drive", "deadline"}
	if !reflect.DeepEqual(core.calls, want) {
		t.Fatalf("packet batch call order = %v, want %v", core.calls, want)
	}
}

func TestSendPacketBorrowsBufferUntilGuestConsumesIt(t *testing.T) {
	instance := &Instance{
		commands:       make(chan command, 1),
		closeRequested: make(chan struct{}),
		done:           make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	packet := []byte{1, 2, 3}
	result := make(chan error, 1)
	go func() {
		result <- instance.SendPacket(ctx, packet)
	}()

	var request command
	select {
	case request = <-instance.commands:
	case <-time.After(time.Second):
		t.Fatal("SendPacket did not enqueue")
	}
	if &request.packet[0] != &packet[0] {
		t.Fatal("SendPacket copied the packet before enqueue")
	}

	cancel()
	select {
	case err := <-result:
		t.Fatalf("SendPacket returned before guest consumption: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	request.response <- nil
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("SendPacket after guest consumption: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendPacket did not return after guest consumption")
	}
}

func TestSendPacketBackpressureRemainsCancelableBeforeEnqueue(t *testing.T) {
	instance := &Instance{
		commands:       make(chan command, 1),
		closeRequested: make(chan struct{}),
		done:           make(chan struct{}),
	}
	instance.commands <- command{kind: commandStart}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- instance.SendPacket(ctx, []byte{1})
	}()

	select {
	case err := <-result:
		t.Fatalf("SendPacket bypassed full command queue: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("SendPacket on full queue returned %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendPacket on full queue ignored context cancellation")
	}
	if got := len(instance.commands); got != 1 {
		t.Fatalf("queued commands = %d, want the original command only", got)
	}
}
