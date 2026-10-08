package eusign_test

import (
	"testing"

	"github.com/dmytro-vovk/go-eusign"
	src "github.com/dmytro-vovk/go-eusign/src"
	"github.com/stretchr/testify/require"
)

// Defaults are applied once per library lifecycle, so a second signer
// must not reset settings changed after the first one was created.
func TestDefaultsAppliedOnce(t *testing.T) {
	_, err := eusign.NewSigner("missing.json", "missing.p7b")
	require.Error(t, err)

	requireOK(t, src.SetModeSettings(&src.ModeSettings{Offline: true}))
	t.Cleanup(func() { requireOK(t, src.SetModeSettings(&src.ModeSettings{Offline: false})) })

	_, err = eusign.NewSigner("missing.json", "missing.p7b")
	require.Error(t, err)

	mode, err := src.GetModeSettings()
	requireOK(t, err)
	require.True(t, mode.Offline)
}

// requireOK accepts src's success value, which is a non-nil Error with code 0.
func requireOK(t *testing.T, err error) {
	t.Helper()

	var e src.Error
	require.ErrorAs(t, err, &e)
	require.Equal(t, src.ErrorNone, e.Code, e.Message)
}

// Finalizing and re-initializing the library (e.g. via NewEncrypter) reloads
// osplm.ini, so the next signer must apply the defaults again.
func TestDefaultsReappliedAfterFinalize(t *testing.T) {
	_, err := eusign.NewSigner("missing.json", "missing.p7b")
	require.Error(t, err)

	require.NoError(t, (&eusign.Signer{}).Finalize())

	_, err = eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	_, err = eusign.NewSigner("missing.json", "missing.p7b")
	require.Error(t, err)

	mode, err := src.GetModeSettings()
	requireOK(t, err)
	require.False(t, mode.Offline)
}
