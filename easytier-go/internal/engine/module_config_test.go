package engine

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/imports/wasi_snapshot_preview1"
)

// wasiWalltimeProbe imports clock_time_get and exports now(), which returns
// the realtime clock value written by WASI at memory offset zero.
var wasiWalltimeProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x0c, 0x02, 0x60, 0x03, 0x7f, 0x7e, 0x7f,
	0x01, 0x7f, 0x60, 0x00, 0x01, 0x7e,
	0x02, 0x29, 0x01, 0x16,
	'w', 'a', 's', 'i', '_', 's', 'n', 'a', 'p', 's', 'h',
	'o', 't', '_', 'p', 'r', 'e', 'v', 'i', 'e', 'w', '1',
	0x0e,
	'c', 'l', 'o', 'c', 'k', '_', 't', 'i', 'm', 'e', '_', 'g', 'e', 't',
	0x00, 0x00,
	0x03, 0x02, 0x01, 0x01,
	0x05, 0x03, 0x01, 0x00, 0x01,
	0x07, 0x10, 0x02,
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
	0x03, 'n', 'o', 'w', 0x00, 0x01,
	0x0a, 0x12, 0x01, 0x10, 0x00,
	0x41, 0x00, 0x42, 0x00, 0x41, 0x00, 0x10, 0x00, 0x1a,
	0x41, 0x00, 0x29, 0x03, 0x00, 0x0b,
}

func TestModuleConfigUsesSystemWalltime(t *testing.T) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		t.Fatalf("instantiate WASI: %v", err)
	}
	compiled, err := runtime.CompileModule(ctx, wasiWalltimeProbe)
	if err != nil {
		t.Fatalf("compile walltime probe: %v", err)
	}
	defer compiled.Close(ctx)

	before := time.Now()
	module, err := runtime.InstantiateModule(ctx, compiled, newModuleConfig())
	if err != nil {
		t.Fatalf("instantiate walltime probe: %v", err)
	}
	results, err := module.ExportedFunction("now").Call(ctx)
	if err != nil {
		t.Fatalf("read WASI walltime: %v", err)
	}
	after := time.Now()
	got := time.Unix(0, int64(results[0]))
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Fatalf("WASI walltime = %s, want system time between %s and %s", got, before, after)
	}
}
