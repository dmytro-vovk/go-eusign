package eusign

import (
	"errors"
	"fmt"

	src "github.com/dmytro-vovk/go-eusign/src"
)

// ErrNoPrivateKey is returned by key-based operations before LoadPrivateKey.
var ErrNoPrivateKey = errors.New("no private key loaded")

// EnvelopCertificate returns the DSTU 4145 key-agreement certificate of the
// key loaded by LoadPrivateKey. For id.gov.ua, send it base64-encoded as the
// get-user-info "cert" parameter; the server then envelopes the user info for
// this certificate and the response must be opened with DevelopData.
func (s *Signer) EnvelopCertificate() ([]byte, error) {
	m.Lock()
	defer m.Unlock()

	pk, err := s.key()
	if err != nil {
		return nil, err
	}

	_, cert, err := src.CtxGetOwnCertificate(pk, src.CertKeyTypeDSTU4145, src.KeyUsageKeyAgreement)
	if err := wrapError(err); err != nil {
		return nil, fmt.Errorf("get own certificate: %w", err)
	}

	return cert, nil
}

// EnvelopData encrypts data for the holders of recipientCerts (CMS
// EnvelopedData, DSTU 4145 key agreement), signing it with the loaded key and
// embedding the sender certificate.
func (s *Signer) EnvelopData(data []byte, recipientCerts ...[]byte) ([]byte, error) {
	if len(recipientCerts) == 0 {
		return nil, errors.New("no recipient certificates")
	}

	m.Lock()
	defer m.Unlock()

	pk, err := s.key()
	if err != nil {
		return nil, err
	}

	enveloped, err := wrapError2(src.CtxEnvelopData(pk, recipientCerts, src.RecipientAppendTypeByIssuerSerial, true, true, data))
	if err != nil {
		return nil, fmt.Errorf("envelop data: %w", err)
	}

	return enveloped, nil
}

// DevelopData decrypts CMS EnvelopedData addressed to the loaded key, such as
// id.gov.ua's get-user-info "encryptedUserInfo" (base64-decode it first). It
// returns the content and information about the sender.
func (s *Signer) DevelopData(enveloped []byte) ([]byte, *src.SenderInfo, error) {
	m.Lock()
	defer m.Unlock()

	pk, err := s.key()
	if err != nil {
		return nil, nil, err
	}

	data, sender, err := src.CtxDevelopData(pk, enveloped, nil)
	if err := wrapError(err); err != nil {
		return nil, nil, fmt.Errorf("develop data: %w", err)
	}

	return data, sender, nil
}

// openPrivateKey reads the key, whose certificates are already saved, keeps
// it for EnvelopData/DevelopData and returns its key-agreement certificate.
func (s *Signer) openPrivateKey(keyData []byte, password string) ([]byte, *src.CertInfoEx, error) {
	m.Lock()
	defer m.Unlock()

	if !src.IsInitialized() {
		return nil, nil, ErrLibraryReloaded
	}

	ctx, err := wrapError2(src.CtxCreate())
	if err != nil {
		return nil, nil, fmt.Errorf("create context: %w", err)
	}

	pkCtx, _, err := src.CtxReadPrivateKeyBinary(ctx, keyData, password)
	if err := wrapError(err); err != nil {
		_ = src.CtxFree(ctx)

		return nil, nil, fmt.Errorf("read private key binary: %w", err)
	}

	infoEx, cert, err := src.CtxGetOwnCertificate(pkCtx, src.CertKeyTypeDSTU4145, src.KeyUsageKeyAgreement)
	if err := wrapError(err); err != nil {
		_ = src.CtxFreePrivateKey(pkCtx)
		_ = src.CtxFree(ctx)

		return nil, nil, fmt.Errorf("get own certificate: %w", err)
	}

	s.setPrivateKey(ctx, pkCtx)

	return cert, infoEx, nil
}

// key returns the loaded key or why it cannot be used. Must be called with m
// held.
func (s *Signer) key() (*src.PrivateKeyContext, error) {
	if s.pk == nil {
		return nil, ErrNoPrivateKey
	}

	if !libLoaded(s.pkGen) {
		return nil, ErrLibraryReloaded
	}

	return s.pk, nil
}

// setPrivateKey replaces the loaded key, freeing the previous one. Must be
// called with m held.
func (s *Signer) setPrivateKey(ctx *src.Context, pk *src.PrivateKeyContext) {
	s.freePrivateKey()
	s.ctx, s.pk, s.pkGen = ctx, pk, libGeneration
}

// freePrivateKey must be called with m held.
func (s *Signer) freePrivateKey() {
	if libLoaded(s.pkGen) { // handles die with the library that made them
		if s.pk != nil {
			_ = src.CtxFreePrivateKey(s.pk)
		}

		if s.ctx != nil {
			_ = src.CtxFree(s.ctx)
		}
	}

	s.ctx, s.pk = nil, nil
}
