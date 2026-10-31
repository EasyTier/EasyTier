package engine

import (
	"context"
	"sync"

	"github.com/easytier/easytier/easytier-go/internal/artifact"
	"github.com/easytier/easytier/easytier-go/internal/contextutil"
	"github.com/metacubex/wazero"
)

// Every Host runs the same embedded core. Compiling it takes a couple of
// seconds of CPU, briefly allocates ~100MB, and maps ~30MB of machine code.
// Hosts in one process share a compilation cache so the core is compiled
// once. The first compiled module stays open for the life of the process,
// which keeps the cache entry available to Hosts created after it closes.
var coreCompilation struct {
	sync.Mutex
	cache  wazero.CompilationCache
	pinned bool
}

func newRuntime(ctx context.Context) wazero.Runtime {
	coreCompilation.Lock()
	if coreCompilation.cache == nil {
		coreCompilation.cache = wazero.NewCompilationCache()
	}
	cache := coreCompilation.cache
	coreCompilation.Unlock()
	return wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCompilationCache(cache))
}

// compileCore returns the core compiled in runtime and a function that drops
// this Host's reference to it once the module has been instantiated.
func compileCore(ctx context.Context, runtime wazero.Runtime) (wazero.CompiledModule, func(), error) {
	// Hold the lock across compilation so concurrent Hosts wait for the first
	// compile and then reuse its result.
	coreCompilation.Lock()
	defer coreCompilation.Unlock()
	compiled, err := runtime.CompileModule(ctx, artifact.Core())
	if err != nil {
		return nil, nil, err
	}
	if !coreCompilation.pinned {
		coreCompilation.pinned = true
		return compiled, func() {}, nil
	}
	return compiled, func() {
		_ = compiled.Close(contextutil.WithoutCancel(ctx))
	}, nil
}
