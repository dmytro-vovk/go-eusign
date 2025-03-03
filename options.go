package eusign

import (
	"github.com/dmytro-vovk/go-eusign/internal/src"
)

type Option func()

func OptionSaveSetting(flag bool) Option {
	return func() {
		if flag {
			src.SetRuntimeParameterInt(src.SaveSettingsParameter, src.SettingsIDAll)
		} else {
			src.SetRuntimeParameterInt(src.SaveSettingsParameter, src.SettingsIDNone)
		}
	}
}
