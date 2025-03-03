package eusign_test

import (
	"testing"

	"github.com/dmytro-vovk/go-eusign"
	"github.com/dmytro-vovk/go-eusign/internal/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypter(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	require.NotNil(t, e)

	var data = []byte("Hello, world!")

	encrypted, mac, err := e.Encrypt(data, src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)

	key, iv, err := e.GetKey()
	require.NoError(t, err)

	newData, err := e.Decrypt(encrypted, mac, key, iv)
	require.NoError(t, err)

	assert.Equal(t, data, newData)
}
