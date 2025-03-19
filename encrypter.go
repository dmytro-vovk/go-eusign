package eusign

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"

	src "github.com/dmytro-vovk/go-eusign/src"
)

type Encrypter struct {
	algo         int
	ctx          *src.AlgoContext
	keyGenerated bool
}

func NewEncrypter(algo int) (*Encrypter, error) {
	if !src.IsInitialized() {
		if err := wrapError(src.Initialize()); err != nil {
			return nil, fmt.Errorf("initialize: %w", err)
		}
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
		src.AlgoCtxFree(ctx)
		src.Finalize()
	}, e.ctx)

	return e, nil
}

func (e *Encrypter) GetDataMAC(data []byte, algo int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	if !e.keyGenerated {
		if err := wrapError(src.AlgoCtxGenerateKey(e.ctx)); err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
	}

	mac, err := src.AlgoCtxGetDataMAC(e.ctx, data, algo)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("get data MAC: %w", err)
	}

	return mac, nil
}

func (e *Encrypter) GetKey() ([]byte, []byte, error) {
	key, iv, err := src.AlgoCtxGetKey(e.ctx)
	if err := wrapError(err); err != nil {
		return nil, nil, fmt.Errorf("get key: %w", err)
	}

	return key, iv, nil
}

func (e *Encrypter) Encrypt(data []byte, algo int) ([]byte, []byte, error) {
	mac, err := e.GetDataMAC(data, algo)
	if err != nil {
		return nil, nil, fmt.Errorf("get data MAC: %w", err)
	}

	encrypted, err := wrapError2(src.AlgoCtxEncrypt(e.ctx, append(data, mac...)))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt data: %w", err)
	}

	return encrypted, mac, nil
}

func (e *Encrypter) Decrypt(data []byte, mac, key, iv []byte) ([]byte, error) {
	if err := wrapError(src.AlgoCtxSetKey(e.ctx, key, iv)); err != nil {
		return nil, fmt.Errorf("set key: %w", err)
	}

	decrypted, err := src.AlgoCtxDecrypt(e.ctx, data)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	mac2 := decrypted[len(decrypted)-len(mac):]

	if !bytes.Equal(mac, mac2) {
		return nil, errors.New("invalid mac")
	}

	return decrypted[:len(decrypted)-len(mac)], nil
}
