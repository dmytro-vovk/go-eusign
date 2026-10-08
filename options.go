package eusign

import (
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
