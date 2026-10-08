package eusign

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"slices"

	src "github.com/dmytro-vovk/go-eusign/src"
)

// ErrInvalidMAC is returned by Encrypter.Decrypt when the MAC does not match.
var ErrInvalidMAC = errors.New("invalid MAC")

type Encrypter struct {
	algo         int
	ctx          *src.AlgoContext
	keyGenerated bool
}

func NewEncrypter(algo int) (*Encrypter, error) {
	m.Lock()
	defer m.Unlock()

	if err := initialize(); err != nil {
		return nil, err
	}

	if err := wrapError(src.SetLogSettings(&src.LogSettings{
		System:         true,
		UseReportAgent: false,
		Address:        "",
		Port:           "",
		OnlyErrors:     false,
	})); err != nil {
		return nil, fmt.Errorf("set log settings: %w", err)
	}

	ctx, err := src.AlgoCtxCreate(algo)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("create context: %w", err)
	}

	e := &Encrypter{
		algo: algo,
		ctx:  ctx,
	}

	runtime.AddCleanup(e, func(ctx *src.AlgoContext) {
		_ = src.AlgoCtxFree(ctx) // the library itself stays loaded until Signer.Finalize
	}, e.ctx)

	return e, nil
}

// GetDataMAC returns a DSTU 7624 MAC of data, macSize bytes long (one of the
// src.AlgoDSTU7624_MAC_* constants). It generates the context key on first use.
func (e *Encrypter) GetDataMAC(data []byte, macSize int) ([]byte, error) {
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	if !e.keyGenerated {
		if err := wrapError(src.AlgoCtxGenerateKey(e.ctx)); err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}

		e.keyGenerated = true
	}

	mac, err := src.AlgoCtxGetDataMAC(e.ctx, data, macSize)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("get data MAC: %w", err)
	}

	return mac, nil
}

func (e *Encrypter) GetKey() ([]byte, []byte, error) {
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	key, iv, err := src.AlgoCtxGetKey(e.ctx)
	if err := wrapError(err); err != nil {
		return nil, nil, fmt.Errorf("get key: %w", err)
	}

	return key, iv, nil
}

// Encrypt appends a macSize-byte MAC (one of the src.AlgoDSTU7624_MAC_*
// constants) to data and encrypts the result. It returns the ciphertext and
// the MAC; data is not modified.
func (e *Encrypter) Encrypt(data []byte, macSize int) ([]byte, []byte, error) {
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	mac, err := e.GetDataMAC(data, macSize)
	if err != nil {
		return nil, nil, fmt.Errorf("get data MAC: %w", err)
	}

	// AlgoCtxEncrypt works in place, so encrypt a fresh buffer.
	encrypted, err := wrapError2(src.AlgoCtxEncrypt(e.ctx, slices.Concat(data, mac)))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt data: %w", err)
	}

	return encrypted, mac, nil
}

// Decrypt reverses Encrypt: it decrypts data, verifies the trailing
// macSize-byte MAC and returns the plaintext without it. macSize must match
// the one passed to Encrypt. data is not modified.
func (e *Encrypter) Decrypt(data []byte, macSize int) ([]byte, error) {
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	if !e.keyGenerated {
		return nil, errors.New("no key: call Encrypt first")
	}

	if macSize <= 0 || len(data) <= macSize {
		return nil, fmt.Errorf("data is %d bytes, need more than the %d-byte MAC", len(data), macSize)
	}

	// AlgoCtxDecrypt works in place, so decrypt a copy.
	decrypted, err := src.AlgoCtxDecrypt(e.ctx, slices.Clone(data))
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	plain, mac := decrypted[:len(decrypted)-macSize], decrypted[len(decrypted)-macSize:]

	expected, err := e.GetDataMAC(plain, macSize)
	if err != nil {
		return nil, fmt.Errorf("get data MAC: %w", err)
	}

	if subtle.ConstantTimeCompare(mac, expected) != 1 {
		return nil, ErrInvalidMAC
	}

	return plain, nil
}
