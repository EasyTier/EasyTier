package hostabi

import (
	"bytes"
	"context"
	"testing"

	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/experimental/wazerotest"
)

func TestCryptoAEADAES128GCMVector(t *testing.T) {
	adapter, module := newCryptoTestModule(t)
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 16)
	writeCryptoTestBytes(t, module, 0, key)
	writeCryptoTestBytes(t, module, 32, nonce)
	writeCryptoTestBytes(t, module, 64, append(plaintext, make([]byte, 16)...))

	status := adapter.cryptoAEADSeal(
		context.Background(),
		module,
		aeadAES128GCM,
		0,
		uint32(len(key)),
		32,
		uint32(len(nonce)),
		0,
		0,
		64,
		uint32(len(plaintext)),
	)
	if status != 0 {
		t.Fatalf("seal status = %d", status)
	}
	got, _ := module.Memory().Read(64, 32)
	want := []byte{
		0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
		0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
		0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
		0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("sealed bytes = %x, want %x", got, want)
	}

	status = adapter.cryptoAEADOpen(
		context.Background(),
		module,
		aeadAES128GCM,
		0,
		uint32(len(key)),
		32,
		uint32(len(nonce)),
		0,
		0,
		64,
		uint32(len(plaintext)),
	)
	if status != 0 {
		t.Fatalf("open status = %d", status)
	}
	got, _ = module.Memory().Read(64, uint32(len(plaintext)))
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("opened bytes = %x, want %x", got, plaintext)
	}
}

func TestCryptoAEADFallbackDoesNotModifyBuffer(t *testing.T) {
	adapter, module := newCryptoTestModule(t)
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	buffer := bytes.Repeat([]byte{7}, 32)
	writeCryptoTestBytes(t, module, 0, key)
	writeCryptoTestBytes(t, module, 32, nonce)
	writeCryptoTestBytes(t, module, 64, buffer)

	status := adapter.cryptoAEADSeal(
		context.Background(),
		module,
		3,
		0,
		uint32(len(key)),
		32,
		uint32(len(nonce)),
		0,
		0,
		64,
		16,
	)
	if status != statusCryptoFallback {
		t.Fatalf("seal status = %d, want fallback", status)
	}
	got, _ := module.Memory().Read(64, uint32(len(buffer)))
	if !bytes.Equal(got, buffer) {
		t.Fatalf("fallback changed buffer: %x", got)
	}
}

func TestCryptoAEADOpenReportsAuthenticationFailure(t *testing.T) {
	adapter, module := newCryptoTestModule(t)
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	buffer := make([]byte, 32)
	buffer[len(buffer)-1] = 1
	writeCryptoTestBytes(t, module, 0, key)
	writeCryptoTestBytes(t, module, 32, nonce)
	writeCryptoTestBytes(t, module, 64, buffer)

	status := adapter.cryptoAEADOpen(
		context.Background(),
		module,
		aeadAES128GCM,
		0,
		uint32(len(key)),
		32,
		uint32(len(nonce)),
		0,
		0,
		64,
		16,
	)
	if status != statusCryptoAuthFailed {
		t.Fatalf("open status = %d, want authentication failure", status)
	}
}

func newCryptoTestModule(t *testing.T) (*Adapter, api.Module) {
	t.Helper()
	return &Adapter{}, wazerotest.NewModule(
		wazerotest.NewMemory(wazerotest.PageSize),
	)
}

func writeCryptoTestBytes(
	t *testing.T,
	module api.Module,
	pointer uint32,
	value []byte,
) {
	t.Helper()
	if !module.Memory().Write(pointer, value) {
		t.Fatalf("write %d bytes at %d", len(value), pointer)
	}
}
