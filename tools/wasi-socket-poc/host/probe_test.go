package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	experimentalsock "github.com/tetratelabs/wazero/experimental/sock"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	preopenedListenerFD  = 3
	timerProgress        = 1 << 0
	secondSocketProgress = 1 << 1
	pendingReadIsolated  = 1 << 2
	idleTimerProgress    = 1 << 3
	probeError           = 1 << 31
	idleMillis           = 200
	busyPollThreshold    = 1_000
)

type capabilityReport struct {
	PublicSocketMethods     []string `json:"public_socket_methods"`
	DynamicConnectionInject bool     `json:"dynamic_connection_injection"`
	UDPResourceInject       bool     `json:"udp_resource_injection"`
	TokioTCPFunctional      bool     `json:"tokio_tcp_functional"`
	ReadinessUnsupported    bool     `json:"readiness_unsupported"`
	FunctionalScenariosRun  bool     `json:"functional_scenarios_run"`
	TimerProgress           bool     `json:"timer_progress"`
	SecondSocketProgress    bool     `json:"second_socket_progress"`
	PendingReadIsolated     bool     `json:"pending_read_isolated"`
	IdleTimerProgress       bool     `json:"idle_timer_progress"`
	IdlePollingEvaluated    bool     `json:"idle_polling_evaluated"`
	PollOneoffCalls         uint64   `json:"poll_oneoff_calls"`
	BusyPollingDetected     bool     `json:"busy_polling_detected"`
	Failure                 string   `json:"failure,omitempty"`
}

func TestWazeroPublicSocketConfig(t *testing.T) {
	methods := publicSocketMethods()
	want := []string{"WithTCPListener"}
	if !slices.Equal(methods, want) {
		t.Fatalf("wazero socket Config methods changed: got %v, want %v", methods, want)
	}

	t.Log("wazero v1.12.0 has no public arbitrary net.Conn or UDP injection method")
}

func TestTokioPreopenedTCPSocketCapability(t *testing.T) {
	wasm := buildGuest(t)
	port := reserveTCPPort(t)
	counter := &pollOneoffCounter{}

	ctx := experimentalsock.WithConfig(
		context.Background(),
		experimentalsock.NewConfig().WithTCPListener("127.0.0.1", port),
	)
	ctx = experimental.WithFunctionListenerFactory(ctx, counter)

	runtimeConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
	t.Cleanup(func() {
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close wazero runtime: %v", err)
		}
	})

	wasi_snapshot_preview1.MustInstantiate(ctx, runtime)
	compiled, err := runtime.CompileModule(ctx, wasm)
	if err != nil {
		t.Fatalf("compile guest: %v", err)
	}

	var guestStderr bytes.Buffer
	moduleConfig := wazero.NewModuleConfig().
		WithStartFunctions("_initialize").
		WithStderr(&guestStderr).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep()
	module, err := runtime.InstantiateModule(ctx, compiled, moduleConfig)
	if err != nil {
		t.Fatalf("instantiate guest: %v", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resultCh := make(chan callResult, 1)
	go func() {
		results, callErr := module.ExportedFunction("run_probe").Call(
			callCtx,
			preopenedListenerFD,
			idleMillis,
		)
		resultCh <- callResult{results: results, err: callErr}
	}()

	pendingConn := dialTCP(t, port)
	defer pendingConn.Close()
	activeConn := dialTCP(t, port)
	defer activeConn.Close()

	if err := activeConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set active connection deadline: %v", err)
	}
	wantEcho := []byte{0x5a}
	if _, err := activeConn.Write(wantEcho); err != nil {
		t.Fatalf("write active connection: %v", err)
	}
	echoCh := make(chan readResult, 1)
	go func() {
		gotEcho := make([]byte, len(wantEcho))
		_, readErr := io.ReadFull(activeConn, gotEcho)
		echoCh <- readResult{data: gotEcho, err: readErr}
	}()

	var gotEcho []byte
	select {
	case echo := <-echoCh:
		if echo.err != nil {
			call := waitForCall(t, callCtx, resultCh)
			if reportKnownReadinessFailure(t, counter, call, guestStderr.String()) {
				return
			}
			t.Fatalf("read active connection echo: %v; guest: %s", echo.err, describeCall(call))
		}
		gotEcho = echo.data
	case call := <-resultCh:
		if reportKnownReadinessFailure(t, counter, call, guestStderr.String()) {
			return
		}
		t.Fatalf(
			"guest returned before echo: %s; poll_oneoff calls=%d\nguest stderr:\n%s",
			describeCall(call),
			counter.count.Load(),
			guestStderr.String(),
		)
	case <-callCtx.Done():
		t.Fatalf("waiting for active connection echo: %v", callCtx.Err())
	}
	if !slices.Equal(gotEcho, wantEcho) {
		t.Fatalf("echo mismatch: got %x, want %x", gotEcho, wantEcho)
	}

	call := <-resultCh
	if call.err != nil {
		t.Fatalf("run guest probe: %v", call.err)
	}
	if len(call.results) != 1 {
		t.Fatalf("unexpected guest result count: %d", len(call.results))
	}
	status := uint32(call.results[0])
	if status&probeError != 0 {
		t.Fatalf("guest probe failed at stage %d", status&^probeError)
	}

	wantStatus := uint32(timerProgress | secondSocketProgress | pendingReadIsolated | idleTimerProgress)
	if status != wantStatus {
		t.Fatalf("guest status 0x%x, want 0x%x", status, wantStatus)
	}

	pollCalls := counter.count.Load()
	report := newCapabilityReport(counter)
	report.TokioTCPFunctional = true
	report.FunctionalScenariosRun = true
	report.TimerProgress = status&timerProgress != 0
	report.SecondSocketProgress = status&secondSocketProgress != 0
	report.PendingReadIsolated = status&pendingReadIsolated != 0
	report.IdleTimerProgress = status&idleTimerProgress != 0
	report.IdlePollingEvaluated = true
	report.BusyPollingDetected = pollCalls > busyPollThreshold
	logCapabilityReport(t, report)
}

type callResult struct {
	results []uint64
	err     error
}

type readResult struct {
	data []byte
	err  error
}

func newCapabilityReport(counter *pollOneoffCounter) capabilityReport {
	return capabilityReport{
		PublicSocketMethods:     publicSocketMethods(),
		DynamicConnectionInject: false,
		UDPResourceInject:       false,
		PollOneoffCalls:         counter.count.Load(),
	}
}

func reportKnownReadinessFailure(
	t *testing.T,
	counter *pollOneoffCounter,
	call callResult,
	guestStderr string,
) bool {
	t.Helper()

	knownFailure := call.err != nil &&
		strings.Contains(call.err.Error(), "wasm error: unreachable") &&
		counter.count.Load() == 1 &&
		strings.Contains(
			guestStderr,
			"unexpected error when polling the I/O driver: Os { code: 58, kind: Unsupported, message: \"Not supported\" }",
		)
	if !knownFailure {
		return false
	}

	report := newCapabilityReport(counter)
	report.ReadinessUnsupported = true
	report.Failure = "Tokio I/O driver aborted after WASIp1 poll_oneoff returned ENOTSUP (58)"
	logCapabilityReport(t, report)
	return true
}

func logCapabilityReport(t *testing.T, report capabilityReport) {
	t.Helper()

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("encode capability report: %v", err)
	}
	t.Logf("capability report:\n%s", reportJSON)
}

func waitForCall(
	t *testing.T,
	ctx context.Context,
	resultCh <-chan callResult,
) callResult {
	t.Helper()

	select {
	case call := <-resultCh:
		return call
	case <-ctx.Done():
		t.Fatalf("waiting for guest result: %v", ctx.Err())
		return callResult{}
	}
}

func describeCall(call callResult) string {
	if call.err != nil {
		return call.err.Error()
	}
	if len(call.results) != 1 {
		return fmt.Sprintf("unexpected result count %d", len(call.results))
	}

	status := uint32(call.results[0])
	if status&probeError != 0 {
		return fmt.Sprintf("guest failure stage %d", status&^probeError)
	}
	return fmt.Sprintf("guest status 0x%x", status)
}

type pollOneoffCounter struct {
	count atomic.Uint64
}

func (c *pollOneoffCounter) NewFunctionListener(
	definition api.FunctionDefinition,
) experimental.FunctionListener {
	if !strings.HasSuffix(definition.DebugName(), ".poll_oneoff") {
		return nil
	}

	return experimental.FunctionListenerFunc(func(
		context.Context,
		api.Module,
		api.FunctionDefinition,
		[]uint64,
		experimental.StackIterator,
	) {
		c.count.Add(1)
	})
}

func publicSocketMethods() []string {
	typeOfConfig := reflect.TypeOf(experimentalsock.NewConfig())
	methods := make([]string, 0, typeOfConfig.NumMethod())
	for i := range typeOfConfig.NumMethod() {
		methods = append(methods, typeOfConfig.Method(i).Name)
	}
	slices.Sort(methods)
	return methods
}

func buildGuest(t *testing.T) []byte {
	t.Helper()

	hostDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve host directory: %v", err)
	}
	guestDir := filepath.Clean(filepath.Join(hostDir, "..", "guest"))
	command := exec.Command("cargo", "build", "--release", "--target", "wasm32-wasip1")
	command.Dir = guestDir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build guest: %v\n%s", err, output)
	}

	wasmPath := filepath.Join(
		guestDir,
		"target",
		"wasm32-wasip1",
		"release",
		"wasi_socket_guest.wasm",
	)
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read guest artifact %s: %v", wasmPath, err)
	}
	return wasm
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved TCP port: %v", err)
	}
	return port
}

func dialTCP(t *testing.T, port int) net.Conn {
	t.Helper()

	address := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	return conn
}
