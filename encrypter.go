package eusign

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"slices"

	src "github.com/dmytro-vovk/go-eusign/src"
)

// ErrInvalidMAC is returned by Encrypter.Decrypt when the MAC does not match.
var ErrInvalidMAC = errors.New("invalid MAC")

// Encrypter encrypts with a symmetric key generated on first use and held in
// its native context, so only the same Encrypter can decrypt. Its methods
// hold the package lock: the native context is not safe for concurrent use.
type Encrypter struct {
	algo  int
	ctx   *src.AlgoContext
	gen   uint64 // library generation ctx belongs to
	key   []byte // nil until first use
	ivLen int
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
		gen:  libGeneration,
	}

	runtime.AddCleanup(e, func(h algoHandle) {
		m.Lock()
		defer m.Unlock()

		if libLoaded(h.gen) { // handles die with the library that made them
			_ = src.AlgoCtxFree(h.ctx)
		}
	}, algoHandle{ctx: e.ctx, gen: e.gen})

	return e, nil
}

type algoHandle struct {
	ctx *src.AlgoContext
	gen uint64
}

// GetDataMAC returns a DSTU 7624 MAC of data, macSize bytes long (one of the
// src.AlgoDSTU7624_MAC_* constants). It generates the context key on first use.
func (e *Encrypter) GetDataMAC(data []byte, macSize int) ([]byte, error) {
	m.Lock()
	defer m.Unlock()

	if err := e.ready(macSize); err != nil {
		return nil, err
	}

	return e.dataMAC(data, macSize)
}

// GetKey returns the context key and the IV of the last operation.
func (e *Encrypter) GetKey() ([]byte, []byte, error) {
	m.Lock()
	defer m.Unlock()
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	if !libLoaded(e.gen) {
		return nil, nil, ErrLibraryReloaded
	}

	key, iv, err := src.AlgoCtxGetKey(e.ctx)
	if err := wrapError(err); err != nil {
		return nil, nil, fmt.Errorf("get key: %w", err)
	}

	return key, iv, nil
}

// Encrypt appends a macSize-byte MAC (one of the src.AlgoDSTU7624_MAC_*
// constants) to data and encrypts the result under a fresh random IV. It
// returns IV || ciphertext and the MAC; data is not modified.
func (e *Encrypter) Encrypt(data []byte, macSize int) ([]byte, []byte, error) {
	m.Lock()
	defer m.Unlock()
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	if err := e.ready(macSize); err != nil {
		return nil, nil, err
	}

	iv := make([]byte, e.ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("generate IV: %w", err)
	}

	if err := wrapError(src.AlgoCtxSetKey(e.ctx, e.key, iv)); err != nil {
		return nil, nil, fmt.Errorf("set IV: %w", err)
	}

	mac, err := e.dataMAC(data, macSize)
	if err != nil {
		return nil, nil, err
	}

	// AlgoCtxEncrypt works in place, so encrypt a fresh buffer.
	encrypted, err := wrapError2(src.AlgoCtxEncrypt(e.ctx, slices.Concat(data, mac)))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt data: %w", err)
	}

	return slices.Concat(iv, encrypted), mac, nil
}

// Decrypt reverses Encrypt: it decrypts data, verifies the trailing
// macSize-byte MAC and returns the plaintext without it. macSize must match
// the one passed to Encrypt. data is not modified.
func (e *Encrypter) Decrypt(data []byte, macSize int) ([]byte, error) {
	m.Lock()
	defer m.Unlock()
	defer runtime.KeepAlive(e) // e.ctx is freed by a cleanup on e

	if err := validMACSize(macSize); err != nil {
		return nil, err
	}

	if !libLoaded(e.gen) {
		return nil, ErrLibraryReloaded
	}

	if e.key == nil {
		return nil, errors.New("no key: call Encrypt first")
	}

	if len(data) <= e.ivLen+macSize {
		return nil, fmt.Errorf("data is %d bytes, need more than the %d-byte IV and %d-byte MAC", len(data), e.ivLen, macSize)
	}

	if err := wrapError(src.AlgoCtxSetKey(e.ctx, e.key, data[:e.ivLen])); err != nil {
		return nil, fmt.Errorf("set IV: %w", err)
	}

	// AlgoCtxDecrypt works in place, so decrypt a copy.
	decrypted, err := src.AlgoCtxDecrypt(e.ctx, slices.Clone(data[e.ivLen:]))
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	plain, mac := decrypted[:len(decrypted)-macSize], decrypted[len(decrypted)-macSize:]

	expected, err := e.dataMAC(plain, macSize)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(mac, expected) != 1 {
		return nil, ErrInvalidMAC
	}

	return plain, nil
}

// ready validates macSize and generates the key on first use. Must be called
// with m held.
func (e *Encrypter) ready(macSize int) error {
	if err := validMACSize(macSize); err != nil {
		return err
	}

	if !libLoaded(e.gen) {
		return ErrLibraryReloaded
	}

	if e.key != nil {
		return nil
	}

	if err := wrapError(src.AlgoCtxGenerateKey(e.ctx)); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	key, iv, err := src.AlgoCtxGetKey(e.ctx)
	if err := wrapError(err); err != nil {
		return fmt.Errorf("get key: %w", err)
	}

	e.key, e.ivLen = key, len(iv)

	return nil
}

// dataMAC must be called with m held, after ready.
func (e *Encrypter) dataMAC(data []byte, macSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	mac, err := src.AlgoCtxGetDataMAC(e.ctx, data, macSize)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("get data MAC: %w", err)
	}

	return mac, nil
}

func validMACSize(macSize int) error {
	switch macSize {
	case src.AlgoDSTU7624_MAC_64, src.AlgoDSTU7624_MAC_128, src.AlgoDSTU7624_MAC_256:
		return nil
	default:
		return fmt.Errorf("invalid MAC size %d", macSize)
	}
}
