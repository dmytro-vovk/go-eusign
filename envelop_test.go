package eusign_test

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/dmytro-vovk/go-eusign"
	src "github.com/dmytro-vovk/go-eusign/src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IIT's public test key from the EUSignCP-EID-Usages samples. Its certificates
// are fetched from the IIT test CA over CMP, so these tests need network.
const (
	iitKeyFile     = "testdata/iit/Key-6.dat"
	iitKeyPassword = "12345677"
	iitIssuerCN    = `Тестовий ЦСК АТ "ІІТ"`
)

func newTestSigner(t *testing.T) *eusign.Signer {
	t.Helper()

	signer, err := eusign.NewSigner("data/CAs.Test.json", "data/CACertificates.Test.All.p7b", eusign.OptionSaveSetting(false))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, signer.Finalize()) })

	return signer
}

func TestDevelopDataWithoutPrivateKey(t *testing.T) {
	signer := newTestSigner(t)

	_, _, err := signer.DevelopData([]byte("not enveloped"))
	require.ErrorIs(t, err, eusign.ErrNoPrivateKey)

	_, err = signer.EnvelopCertificate()
	require.ErrorIs(t, err, eusign.ErrNoPrivateKey)
}

// TestEnvelopDevelopData mirrors the id.gov.ua flow: the relying party sends
// its key-agreement certificate (EnvelopCertificate) as get-user-info's cert
// parameter, the server envelopes the user info for it, and the relying
// party opens it with DevelopData.
func TestEnvelopDevelopData(t *testing.T) {
	signer := newTestSigner(t)

	_, _, err := signer.LoadPrivateKey(iitKeyFile, iitKeyPassword, iitIssuerCN)
	require.NoError(t, err)

	cert, err := signer.EnvelopCertificate()
	require.NoError(t, err)
	require.NotEmpty(t, cert)

	userInfo := []byte(`{"subjectcn":"plaintext-marker-7f3a"}`)

	enveloped, err := signer.EnvelopData(userInfo, cert)
	require.NoError(t, err)
	assert.NotContains(t, string(enveloped), "plaintext-marker-7f3a")

	developed, sender, err := signer.DevelopData(enveloped)
	require.NoError(t, err)
	assert.Equal(t, userInfo, developed)
	require.NotNil(t, sender)
	assert.Equal(t, "Тестовий Користувач 1", sender.SubjCN)

	_, _, err = signer.DevelopData(enveloped[:len(enveloped)/2])
	require.Error(t, err, "truncated envelope")
}

// TestDevelopDataForAnotherCertificate opens the encryptedUserInfo that IIT's
// C++ id.gov.ua sample (EUSignUsage.cpp) hard-codes for an earlier certificate
// of this key: an envelope for any certificate other than EnvelopCertificate
// cannot be opened, which is why get-user-info's cert must be that one.
func TestDevelopDataForAnotherCertificate(t *testing.T) {
	signer := newTestSigner(t)

	_, _, err := signer.LoadPrivateKey(iitKeyFile, iitKeyPassword, iitIssuerCN)
	require.NoError(t, err)

	b64, err := os.ReadFile("testdata/iit/encryptedUserInfo.b64")
	require.NoError(t, err)

	encryptedUserInfo, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64)))
	require.NoError(t, err)

	_, _, err = signer.DevelopData(encryptedUserInfo)
	var libErr src.Error
	require.ErrorAs(t, err, &libErr)
	assert.Equal(t, src.ErrorNotReceiver, libErr.Code)
}

func TestSignerKeyUnusableAfterFinalize(t *testing.T) {
	signer, err := eusign.NewSigner("data/CAs.Test.json", "data/CACertificates.Test.All.p7b", eusign.OptionSaveSetting(false))
	require.NoError(t, err)

	_, _, err = signer.LoadPrivateKey(iitKeyFile, iitKeyPassword, iitIssuerCN)
	require.NoError(t, err)

	require.NoError(t, signer.Finalize())

	// Another signer reloads the library; the first signer's key is gone.
	other := newTestSigner(t)
	require.NotNil(t, other)

	_, _, err = signer.DevelopData([]byte("enveloped"))
	require.ErrorIs(t, err, eusign.ErrNoPrivateKey)
}

func TestKeyFromPreviousLibraryLoadIsRejected(t *testing.T) {
	signer := newTestSigner(t)

	_, _, err := signer.LoadPrivateKey(iitKeyFile, iitKeyPassword, iitIssuerCN)
	require.NoError(t, err)

	// Finalizing through a different signer unloads the library under signer.
	other, err := eusign.NewSigner("data/CAs.Test.json", "data/CACertificates.Test.All.p7b", eusign.OptionSaveSetting(false))
	require.NoError(t, err)
	require.NoError(t, other.Finalize())

	_ = newTestSigner(t) // reload

	_, err = signer.EnvelopCertificate()
	require.ErrorIs(t, err, eusign.ErrLibraryReloaded)
}
