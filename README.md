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

Tests that load keys need IIT test data in `data/` (gitignored): `CAs.Test.json`, `CACertificates.Test.All.p7b`, `Key-6.dat`.
