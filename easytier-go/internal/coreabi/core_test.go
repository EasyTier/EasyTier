package coreabi

import (
	"context"
	"testing"

	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/experimental/wazerotest"
)

func TestCallOneCachesFunction(t *testing.T) {
	callCount := 0
	increment := wazerotest.NewFunction(func(
		_ context.Context,
		_ api.Module,
		value uint64,
	) uint64 {
		callCount++
		return value + 1
	})
	increment.ExportNames = []string{"increment"}
	module := wazerotest.NewModule(nil, increment)
	core := &Core{
		module:    module,
		functions: make(map[string]guestFunction),
	}

	for i := uint64(0); i < 2; i++ {
		result, err := core.callOne(context.Background(), "increment", i)
		if err != nil {
			t.Fatalf("call increment: %v", err)
		}
		if result != i+1 {
			t.Fatalf("increment result = %d, want %d", result, i+1)
		}
	}
	if callCount != 2 {
		t.Fatalf("call count = %d, want 2", callCount)
	}
	if len(core.functions) != 1 {
		t.Fatalf("cached functions = %d, want 1", len(core.functions))
	}
}

func TestCallOneValidatesSignature(t *testing.T) {
	noResult := wazerotest.NewFunction(func(
		_ context.Context,
		_ api.Module,
	) {
	})
	noResult.ExportNames = []string{"no_result"}
	module := wazerotest.NewModule(nil, noResult)
	core := &Core{
		module:    module,
		functions: make(map[string]guestFunction),
	}

	_, err := core.callOne(context.Background(), "no_result")
	if err == nil {
		t.Fatal("call function without result: expected error")
	}
}
