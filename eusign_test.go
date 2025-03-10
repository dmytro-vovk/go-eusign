package eusign_test

import (
	"testing"

	"github.com/dmytro-vovk/go-eusign"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	signer, err := eusign.NewSigner("data/CAs.Test.json", "data/CACertificates.Test.All.p7b", eusign.OptionSaveSetting(false))
	require.NoError(t, err)
	require.NotNil(t, signer)

	t.Cleanup(func() {
		require.NoError(t, signer.Finalize())
	})

	pk, info, err := signer.LoadPrivateKey("data/Key-6.dat", "12345")
	require.NoError(t, err)
	require.NotNil(t, pk)

	t.Logf("Key info: %+v", info)
}
