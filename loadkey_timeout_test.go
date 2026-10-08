package eusign_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dmytro-vovk/go-eusign"
	"github.com/stretchr/testify/require"
)

// blackHole is a non-routable address: TCP SYNs are silently dropped, so
// connect() hangs until the OS gives up (75s+ on macOS/Linux).
const blackHole = "10.255.255.1"

func blackHoledCAs(t *testing.T, n int, extra ...eusign.CA) string {
	t.Helper()

	cas := make([]eusign.CA, n, n+len(extra))
	for i := range cas {
		cas[i] = eusign.CA{
			IssuerCNs:  []string{"Black Hole CA " + string(rune('A'+i))},
			Address:    blackHole,
			CmpAddress: blackHole,
		}
	}

	cas = append(cas, extra...)

	data, err := json.Marshal(cas)
	require.NoError(t, err)

	fileName := filepath.Join(t.TempDir(), "CAs.json")
	require.NoError(t, os.WriteFile(fileName, data, 0o600))

	return fileName
}

func TestLoadPrivateKeyBlackHoledCMPIsBounded(t *testing.T) {
	signer, err := eusign.NewSigner(
		blackHoledCAs(t, 4),
		"data/CACertificates.Test.All.p7b",
		eusign.OptionSaveSetting(false),
		eusign.OptionConnectionsTimeout(2*time.Second),
	)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, signer.Finalize()) })

	start := time.Now()
	_, _, err = signer.LoadPrivateKey("data/Key-6.dat", "12345", "")
	elapsed := time.Since(start)

	require.Error(t, err)
	require.ErrorContains(t, err, blackHole)
	require.Less(t, elapsed, 10*time.Second, "LoadPrivateKey must give up on black-holed CMP servers")
}

func TestLoadPrivateKeyDefaultConnectionsTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for DefaultConnectionsTimeout")
	}

	signer, err := eusign.NewSigner(blackHoledCAs(t, 2), "data/CACertificates.Test.All.p7b", eusign.OptionSaveSetting(false))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, signer.Finalize()) })

	start := time.Now()
	_, _, err = signer.LoadPrivateKey("data/Key-6.dat", "12345", "")
	elapsed := time.Since(start)

	require.Error(t, err)
	require.Less(t, elapsed, eusign.DefaultConnectionsTimeout+5*time.Second)
}

// LoadPrivateKey returns on the first CMP answer while requests to other CAs
// are still in flight; Finalize must wait for them instead of unloading the
// library under their feet (that used to SIGSEGV the process).
func TestFinalizeWaitsForInFlightCMP(t *testing.T) {
	const timeout = 3 * time.Second

	signer, err := eusign.NewSigner(
		blackHoledCAs(t, 4, eusign.CA{
			IssuerCNs:  []string{"Тестовий надавач електронних довірчих послуг"},
			Address:    "ca-test.czo.gov.ua",
			CmpAddress: "ca-test.czo.gov.ua",
		}),
		"data/CACertificates.Test.All.p7b",
		eusign.OptionSaveSetting(false),
		eusign.OptionConnectionsTimeout(timeout),
	)
	require.NoError(t, err)

	start := time.Now()
	_, _, err = signer.LoadPrivateKey("data/Key-6.dat", "12345", "")
	elapsed := time.Since(start)

	if err != nil && strings.Contains(err.Error(), "could not get private key certificate") {
		require.NoError(t, signer.Finalize())
		t.Skipf("test CMP server unreachable: %v", err)
	}

	require.Less(t, elapsed, timeout, "should return on the first CMP answer")
	require.NoError(t, signer.Finalize())
	require.GreaterOrEqual(t, time.Since(start), timeout, "Finalize should wait for in-flight CMP requests")
}
