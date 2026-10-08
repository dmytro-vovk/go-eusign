package eusign_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/dmytro-vovk/go-eusign"
	src "github.com/dmytro-vovk/go-eusign/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypter(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)
	require.NotNil(t, e)

	data := []byte("Hello, world!")
	original := append([]byte(nil), data...)

	encrypted, mac, err := e.Encrypt(data, src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)
	assert.Len(t, mac, src.AlgoDSTU7624_MAC_256)
	assert.Equal(t, original, data, "Encrypt must not modify its input")

	ciphertext := append([]byte(nil), encrypted...)

	decrypted, err := e.Decrypt(encrypted, src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
	assert.Equal(t, ciphertext, encrypted, "Decrypt must not modify its input")

	// The key survives Decrypt, so a second message round-trips too.
	encrypted2, _, err := e.Encrypt([]byte("second"), src.AlgoDSTU7624_MAC_128)
	require.NoError(t, err)

	decrypted2, err := e.Decrypt(encrypted2, src.AlgoDSTU7624_MAC_128)
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), decrypted2)
}

func TestEncrypterDecryptRejectsTampering(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	encrypted, _, err := e.Encrypt([]byte("Hello, world!"), src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)

	tampered := append([]byte(nil), encrypted...)
	tampered[0] ^= 0x01

	_, err = e.Decrypt(tampered, src.AlgoDSTU7624_MAC_256)
	require.ErrorIs(t, err, eusign.ErrInvalidMAC)

	_, err = e.Decrypt(encrypted[:src.AlgoDSTU7624_MAC_256-1], src.AlgoDSTU7624_MAC_256)
	require.Error(t, err, "data shorter than the MAC")
}

func TestEncrypterDecryptWithoutKey(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	_, err = e.Decrypt(make([]byte, 64), src.AlgoDSTU7624_MAC_256)
	require.Error(t, err)
}

func TestEncrypterUsesFreshIVPerMessage(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	data := []byte("the same plaintext, twice")

	first, _, err := e.Encrypt(data, src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)

	second, _, err := e.Encrypt(data, src.AlgoDSTU7624_MAC_256)
	require.NoError(t, err)

	assert.NotEqual(t, first, second)

	// Messages decrypt in any order.
	for _, encrypted := range [][]byte{second, first} {
		decrypted, err := e.Decrypt(encrypted, src.AlgoDSTU7624_MAC_256)
		require.NoError(t, err)
		assert.Equal(t, data, decrypted)
	}
}

func TestEncrypterRejectsInvalidMACSize(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	for _, size := range []int{-1, 0, 7, 33} {
		_, _, err := e.Encrypt([]byte("data"), size)
		require.Error(t, err, "Encrypt macSize %d", size)

		_, err = e.Decrypt(make([]byte, 128), size)
		require.Error(t, err, "Decrypt macSize %d", size)
	}
}

func TestEncrypterConcurrentUse(t *testing.T) {
	e, err := eusign.NewEncrypter(src.AlgoDSTU7624_CFB_256)
	require.NoError(t, err)

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			data := []byte(fmt.Sprintf("message %d", i))

			encrypted, _, err := e.Encrypt(data, src.AlgoDSTU7624_MAC_128)
			if !assert.NoError(t, err) {
				return
			}

			decrypted, err := e.Decrypt(encrypted, src.AlgoDSTU7624_MAC_128)
			assert.NoError(t, err)
			assert.Equal(t, data, decrypted)
		}()
	}

	wg.Wait()
}
