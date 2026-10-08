package eusign_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	signer := newTestSigner(t)

	pk, info, err := signer.LoadPrivateKey(iitKeyFile, iitKeyPassword, "")
	require.NoError(t, err)
	require.NotNil(t, pk)

	t.Logf("Key info: %+v", info)
}
