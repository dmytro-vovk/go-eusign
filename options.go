package eusign

import (
	"math"
	"time"

	src "github.com/dmytro-vovk/go-eusign/src"
)

// Option adjusts library settings. Options run while the package lock is held,
// so they must not call NewSigner, NewEncrypter or Signer.Finalize.
type Option func()

func OptionSaveSetting(flag bool) Option {
	return func() {
		if flag {
			_ = src.SetRuntimeParameterInt(src.SaveSettingsParameter, src.SettingsIDAll)
		} else {
			_ = src.SetRuntimeParameterInt(src.SaveSettingsParameter, src.SettingsIDNone)
		}
	}
}

// OptionConnectionsTimeout overrides DefaultConnectionsTimeout (millisecond
// resolution, clamped to [1ms, MaxInt32 ms]). The setting is process-global and
// stays in effect until changed or the library is finalized.
func OptionConnectionsTimeout(timeout time.Duration) Option {
	ms := min(max(timeout.Milliseconds(), 1), math.MaxInt32)

	return func() {
		_ = src.SetRuntimeParameterInt(src.ConnectionsTimeoutParameter, int(ms))
	}
}
