# go-eusign

> [!WARNING]  
> Work in progress. Do not use.

Go library/wrapper for [id.gov.ua](https://id.gov.ua/) integrated system of electronic identification connectivity.

## Native libraries

`src/` bundles IIT EUSignCP **2026-07-02** (C sources and `src/lib/{darwin,linux/64,linux/arm,linux/32,windows/*}`).
The library is loaded at runtime with `dlopen`, so it must be on the loader path:

```bash
make test   # sets LD_LIBRARY_PATH / DYLD_LIBRARY_PATH for the current platform
```

Tests that load keys need IIT test data in `data/` (gitignored): `CAs.Test.json`, `CACertificates.Test.All.p7b`.

`testdata/iit/Key-6.dat` (password `12345677`) is IIT's public test key from the EUSignCP-EID-Usages samples;
its certificates come from the IIT test CA over CMP, so `envelop_test.go` and `TestNew` need network.

## Network timeouts

Every network exchange of the native library (CMP, OCSP, TSP) is bounded by its `ConnectionsTimeout`
runtime parameter, set to `DefaultConnectionsTimeout` (10s) and overridable with `OptionConnectionsTimeout`.
`Signer.LoadPrivateKey` with an empty issuer CN queries every CA's CMP server in parallel, returns on the first
certificate found, and otherwise reports each CA's error. Requests still in flight finish in the background;
`Signer.Finalize`, `NewSigner` and `NewEncrypter` wait for them (at most one timeout) before touching the library.

## id.gov.ua user info

`get-user-info` returns `encryptedUserInfo`: CMS EnvelopedData (DSTU 4145 key agreement) addressed to the
certificate passed as the `cert` parameter. Decrypt it with the matching private key, as IIT's samples do with
`CtxDevelopData`:

```go
signer, _ := eusign.NewSigner(casFile, caCertsFile)
_, _, _ = signer.LoadPrivateKey(keyFile, password, issuerCN)

cert, _ := signer.EnvelopCertificate() // send base64(cert) as get-user-info's "cert"

// response.EncryptedUserInfo is the base64-decoded "encryptedUserInfo" JSON field
userInfo, sender, _ := signer.DevelopData(response.EncryptedUserInfo)
```

`Encrypter` (DSTU 7624 with a symmetric key held in its context) cannot decrypt it.
`Encrypter.Encrypt(data, macSize)` appends a MAC and returns `IV || ciphertext` under a fresh random IV;
`Encrypter.Decrypt(data, macSize)` on the same `Encrypter` verifies and strips the MAC.

Once any `Signer.Finalize` unloads the library, existing keys and `Encrypter`s return `ErrLibraryReloaded`.
