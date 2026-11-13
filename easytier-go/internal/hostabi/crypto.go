package hostabi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"sync"

	"github.com/metacubex/wazero/api"
)

const (
	aeadAES128GCM          uint32 = 1
	aeadAES256GCM          uint32 = 2
	aeadCacheCapacity             = 64
	statusCryptoAuthFailed int32  = -10
	statusCryptoFallback   int32  = -11
)

var (
	cryptoAEADParameterTypes = []api.ValueType{
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
		api.ValueTypeI32,
	}
	hostI32ResultTypes = []api.ValueType{api.ValueTypeI32}
)

type aeadCacheKey struct {
	algorithm uint32
	key       [32]byte
}

type aeadCache struct {
	mu      sync.Mutex
	entries map[aeadCacheKey]cipher.AEAD
	order   [aeadCacheCapacity]aeadCacheKey
	size    int
	next    int
}

func (adapter *Adapter) cryptoAEADFunction(open bool) api.GoModuleFunction {
	return api.GoModuleFunc(func(ctx context.Context, module api.Module, stack []uint64) {
		function := adapter.cryptoAEADSeal
		if open {
			function = adapter.cryptoAEADOpen
		}
		stack[0] = api.EncodeI32(function(
			ctx,
			module,
			api.DecodeU32(stack[0]),
			api.DecodeU32(stack[1]),
			api.DecodeU32(stack[2]),
			api.DecodeU32(stack[3]),
			api.DecodeU32(stack[4]),
			api.DecodeU32(stack[5]),
			api.DecodeU32(stack[6]),
			api.DecodeU32(stack[7]),
			api.DecodeU32(stack[8]),
		))
	})
}

func (cache *aeadCache) get(
	algorithm uint32,
	key []byte,
) (cipher.AEAD, bool) {
	if (algorithm != aeadAES128GCM || len(key) != 16) &&
		(algorithm != aeadAES256GCM || len(key) != 32) {
		return nil, false
	}

	var cacheKey aeadCacheKey
	cacheKey.algorithm = algorithm
	copy(cacheKey.key[:], key)

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cached := cache.entries[cacheKey]; cached != nil {
		return cached, true
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	if cache.entries == nil {
		cache.entries = make(map[aeadCacheKey]cipher.AEAD, aeadCacheCapacity)
	}
	if cache.size < aeadCacheCapacity {
		cache.order[cache.size] = cacheKey
		cache.size++
	} else {
		delete(cache.entries, cache.order[cache.next])
		cache.order[cache.next] = cacheKey
		cache.next = (cache.next + 1) % aeadCacheCapacity
	}
	cache.entries[cacheKey] = aead
	return aead, true
}

func (adapter *Adapter) cryptoAEADSeal(
	_ context.Context,
	module api.Module,
	algorithm uint32,
	keyPointer uint32,
	keyLength uint32,
	noncePointer uint32,
	nonceLength uint32,
	aadPointer uint32,
	aadLength uint32,
	bufferPointer uint32,
	textLength uint32,
) int32 {
	nonce, aad, aead, ok := adapter.cryptoAEADInputs(
		module,
		algorithm,
		keyPointer,
		keyLength,
		noncePointer,
		nonceLength,
		aadPointer,
		aadLength,
	)
	if !ok {
		return statusCryptoFallback
	}
	if textLength > ^uint32(0)-uint32(aead.Overhead()) {
		return statusCryptoFallback
	}
	buffer, ok := module.Memory().Read(
		bufferPointer,
		textLength+uint32(aead.Overhead()),
	)
	if !ok {
		return statusCryptoFallback
	}
	aead.Seal(buffer[:0], nonce, buffer[:textLength], aad)
	return 0
}

func (adapter *Adapter) cryptoAEADOpen(
	_ context.Context,
	module api.Module,
	algorithm uint32,
	keyPointer uint32,
	keyLength uint32,
	noncePointer uint32,
	nonceLength uint32,
	aadPointer uint32,
	aadLength uint32,
	bufferPointer uint32,
	textLength uint32,
) int32 {
	nonce, aad, aead, ok := adapter.cryptoAEADInputs(
		module,
		algorithm,
		keyPointer,
		keyLength,
		noncePointer,
		nonceLength,
		aadPointer,
		aadLength,
	)
	if !ok {
		return statusCryptoFallback
	}
	if textLength > ^uint32(0)-uint32(aead.Overhead()) {
		return statusCryptoFallback
	}
	buffer, ok := module.Memory().Read(
		bufferPointer,
		textLength+uint32(aead.Overhead()),
	)
	if !ok {
		return statusCryptoFallback
	}
	opened, err := aead.Open(buffer[:0], nonce, buffer, aad)
	if err != nil {
		return statusCryptoAuthFailed
	}
	if len(opened) != int(textLength) {
		return statusCryptoAuthFailed
	}
	return 0
}

func (adapter *Adapter) cryptoAEADInputs(
	module api.Module,
	algorithm uint32,
	keyPointer uint32,
	keyLength uint32,
	noncePointer uint32,
	nonceLength uint32,
	aadPointer uint32,
	aadLength uint32,
) ([]byte, []byte, cipher.AEAD, bool) {
	key, ok := readCryptoBytes(module, keyPointer, keyLength)
	if !ok {
		return nil, nil, nil, false
	}
	aead, ok := adapter.aeads.get(algorithm, key)
	if !ok {
		return nil, nil, nil, false
	}
	nonce, ok := readCryptoBytes(module, noncePointer, nonceLength)
	if !ok || len(nonce) != aead.NonceSize() {
		return nil, nil, nil, false
	}
	aad, ok := readCryptoBytes(module, aadPointer, aadLength)
	if !ok {
		return nil, nil, nil, false
	}
	return nonce, aad, aead, true
}

func readCryptoBytes(
	module api.Module,
	pointer uint32,
	length uint32,
) ([]byte, bool) {
	if length == 0 {
		return nil, true
	}
	return module.Memory().Read(pointer, length)
}
