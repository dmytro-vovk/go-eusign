package eusign

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	src "github.com/dmytro-vovk/go-eusign/src"
)

type Signer struct {
	cas []CA
}

var (
	m               sync.Mutex
	defaultsApplied bool // guarded by m; reset whenever the library is (re)initialized

	// inFlight tracks CMP requests that may outlive the LoadPrivateKey call that
	// started them. Add is called with m held; configure and finalize wait for
	// them (also with m held) before touching process-global library state.
	inFlight sync.WaitGroup
)

// NewSigner configures process-global library settings, so it holds m throughout.
func NewSigner(casFile, caCertFile string, options ...Option) (*Signer, error) {
	m.Lock()
	defer m.Unlock()

	if err := configure(options); err != nil {
		return nil, err
	}

	cas, err := loadCAs(casFile)
	if err != nil {
		return nil, fmt.Errorf("loading CAs: %w", err)
	}

	caCertificates, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate file: %v", err)
	}

	for _, ca := range cas {
		var ocspAccessInfoSettings src.OCSPAccessInfoSettings
		ocspAccessInfoSettings.Address = ca.Address
		ocspAccessInfoSettings.Port = ca.OCSPAccessPointPort

		for _, issuerCN := range ca.IssuerCNs {
			ocspAccessInfoSettings.IssuerCN = issuerCN

			if err := wrapError(src.SetOCSPAccessInfoSettings(&ocspAccessInfoSettings)); err != nil {
				return nil, fmt.Errorf("setting OCSP access info: %w", err)
			}
		}
	}

	if err := wrapError(src.SaveCertificates(caCertificates)); err != nil {
		return nil, fmt.Errorf("saving CA certificates: %w", err)
	}

	return &Signer{cas: cas}, err
}

// initialize loads the library if needed, after background CMP requests have
// finished so callers can safely change process-global settings. Must be
// called with m held.
func initialize() error {
	inFlight.Wait()

	if src.IsInitialized() {
		return nil
	}

	if err := wrapError(src.Initialize()); err != nil {
		return fmt.Errorf("initializing: %w", err)
	}

	defaultsApplied = false // a fresh load re-reads osplm.ini

	return nil
}

// finalize unloads the library once background CMP requests (each bounded by
// ConnectionsTimeout) have finished.
func finalize() error {
	m.Lock()
	defer m.Unlock()

	inFlight.Wait()

	defaultsApplied = false

	return wrapError(src.Finalize())
}

// configure initializes the library and applies defaults once per library
// lifecycle, then the options. Must be called with m held.
func configure(options []Option) error {
	if err := initialize(); err != nil {
		return err
	}

	if !defaultsApplied {
		if err := applyDefaults(); err != nil {
			return fmt.Errorf("applying defaults: %w", err)
		}

		defaultsApplied = true
	}

	for _, fn := range options {
		fn()
	}

	return nil
}

// applyDefaults ignores DoesNeedSetSettings: IIT's bundled osplm.ini enables
// offline mode and points the certificate store at /data/certificates.
func applyDefaults() error {
	if err := wrapError(src.SetRuntimeParameterInt(src.SaveSettingsParameter, src.SettingsIDNone)); err != nil {
		return fmt.Errorf("set save settings parameter: %w", err)
	}

	// ConnectionsTimeout is in milliseconds.
	if err := wrapError(src.SetRuntimeParameterInt(src.ConnectionsTimeoutParameter, int(DefaultConnectionsTimeout.Milliseconds()))); err != nil {
		return fmt.Errorf("set connections timeout: %w", err)
	}

	if err := wrapError(src.SetFileStoreSettings(&src.FileStoreSettings{ExpireTime: 3600})); err != nil {
		return fmt.Errorf("set file store setting: %w", err)
	}

	if err := wrapError(src.SetProxySettings(&src.ProxySettings{})); err != nil {
		return fmt.Errorf("set proxy settings: %w", err)
	}

	if err := wrapError(src.SetTSPSettings(&src.TSPSettings{
		GetStamps: true,
		Address:   DefaultTSPAddress,
		Port:      DefaultTSPPort,
	})); err != nil {
		return fmt.Errorf("set TSP settings: %w", err)
	}

	if err := wrapError(src.SetOCSPResponseExpireTime(30)); err != nil {
		return fmt.Errorf("set OCSP response expire time: %w", err)
	}

	if err := wrapError(src.SetOCSPSettings(&src.OCSPSettings{
		Use:         true,
		BeforeStore: true,
		Address:     DefaultOCSPAddress,
		Port:        DefaultOCSPPort,
	})); err != nil {
		return fmt.Errorf("set OCSP response expire time: %w", err)
	}

	if err := wrapError(src.SetOCSPAccessInfoModeSettings(&src.OCSPAccessInfoModeSettings{Enabled: true})); err != nil {
		return fmt.Errorf("set OCSP access info mode: %w", err)
	}

	if err := wrapError(src.SetLDAPSettings(&src.LDAPSettings{})); err != nil {
		return fmt.Errorf("set LDAP settings: %w", err)
	}

	if err := wrapError(src.SetCMPSettings(&src.CMPSettings{Port: "80"})); err != nil {
		return fmt.Errorf("set CMP settings: %w", err)
	}

	if err := wrapError(src.SetLogSettings(&src.LogSettings{System: true})); err != nil {
		return fmt.Errorf("set CMP settings: %w", err)
	}

	if err := wrapError(src.SetModeSettings(&src.ModeSettings{Offline: false})); err != nil {
		return fmt.Errorf("set mode settings: %w", err)
	}

	return nil
}

func loadCAs(fileName string) ([]CA, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer func(c io.Closer) { _ = c.Close() }(f)

	var cas []CA
	if err := json.NewDecoder(f).Decode(&cas); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}

	return cas, nil
}

func (s *Signer) Finalize() error {
	return finalize()
}

func (s *Signer) Hash(data []byte, algo HashAlgo) ([]byte, error) {
	ctx, err := wrapError2(src.CtxCreate())
	if err != nil {
		return nil, fmt.Errorf("create context: %w", err)
	}

	defer func(ctx *src.Context) { _ = src.CtxFree(ctx) }(ctx)

	hash, err := wrapError2(src.CtxHashData(ctx, int(algo), data))
	if err != nil {
		return nil, fmt.Errorf("hash data: %w", err)
	}

	return hash, nil
}

// findPrivateKeyCertificate asks every CA's CMP server in parallel and returns
// the first certificate found. Each request is bounded by the library's
// ConnectionsTimeout; requests still in flight after the first success finish
// in the background (Finalize waits for them). If no CA has the certificate,
// the per-CA errors are joined.
func (s *Signer) findPrivateKeyCertificate(info []byte) ([]byte, error) {
	type result struct {
		addr  string
		certs []byte
		err   error
	}

	results := make(chan result, len(s.cas)) // buffered: late senders never block

	var addrs []string

	for _, ca := range s.cas {
		if ca.CmpAddress != "" {
			addrs = append(addrs, ca.CmpAddress)
		}
	}

	m.Lock()
	inFlight.Add(len(addrs))
	m.Unlock()

	for _, addr := range addrs {
		go func() {
			defer inFlight.Done()

			certs, err := wrapError2(src.GetCertificatesByKeyInfo(info, []string{addr}, []string{"80"}))
			results <- result{addr: addr, certs: certs, err: err}
		}()
	}

	errs := make([]error, 0, len(addrs))

	for range addrs {
		r := <-results
		if r.err == nil && len(r.certs) > 0 {
			log.Printf("Got private key certificate from %s", r.addr)

			return r.certs, nil
		}

		if r.err == nil {
			r.err = errors.New("empty response")
		}

		errs = append(errs, fmt.Errorf("%s: %w", r.addr, r.err))
	}

	if len(errs) == 0 {
		return nil, errors.New("could not get private key certificate: no CMP servers configured")
	}

	return nil, fmt.Errorf("could not get private key certificate: %w", errors.Join(errs...))
}

func (s *Signer) LoadPrivateKey(fileName, password, cn string) ([]byte, *src.CertInfoEx, error) {
	// Read private key

	keyData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, nil, fmt.Errorf("read key data: %w", err)
	}

	info, err := wrapError2(src.GetKeyInfoBinary(keyData, password))
	if err != nil {
		return nil, nil, fmt.Errorf("get key info: %w", err)
	}

	// Find private key certificate

	var pkCertsCMP []byte

	if cn != "" {
		for _, ca := range s.cas {
			for _, icn := range ca.IssuerCNs {
				if icn == cn {
					if ca.CmpAddress != "" {
						pkCertsCMP, err = wrapError2(src.GetCertificatesByKeyInfo(info, []string{ca.CmpAddress}, []string{"80"}))
						if err != nil {
							return nil, nil, fmt.Errorf("get private key certificate from %s: %w", ca.CmpAddress, err)
						}
					}

					break
				}
			}
		}
	} else if pkCertsCMP, err = s.findPrivateKeyCertificate(info); err != nil {
		return nil, nil, err
	}

	if pkCertsCMP == nil {
		return nil, nil, errors.New("could not get private key certificate")
	}

	var pkCerts [][]byte

	for i := 0; ; i++ {
		infoEx, cert, err := src.GetCertificateFromSignedData(i, pkCertsCMP)
		if err.(src.Error).Code == src.WarningEndOfEnum {
			break
		}

		if err := wrapError(err); err != nil {
			return nil, nil, fmt.Errorf("get certificate from signed data: %w", err)
		}

		if infoEx.SubjType == src.SubjectTypeEndUser {
			pkCerts = append(pkCerts, cert)
		}
	}

	for _, pkCert := range pkCerts {
		if err := wrapError(src.SaveCertificate(pkCert)); err != nil {
			return nil, nil, fmt.Errorf("save certificate: %w", err)
		}
	}

	// Save private key

	ctx, err := wrapError2(src.CtxCreate())
	if err != nil {
		return nil, nil, fmt.Errorf("create context: %w", err)
	}

	{
		pkCtx, _, err := src.CtxReadPrivateKeyBinary(ctx, keyData, password)
		if err := wrapError(err); err != nil {
			return nil, nil, fmt.Errorf("read private key binary: %w", err)
		}

		infoEx, cert, err := src.CtxGetOwnCertificate(pkCtx, src.CertKeyTypeDSTU4145, src.KeyUsageKeyAgreement)
		if err := wrapError(err); err != nil {
			return nil, nil, fmt.Errorf("get own certificate: %w", err)
		}

		return cert, infoEx, nil
	}
}
