package eusign

import (
	src "github.com/dmytro-vovk/go-eusign/src"
)

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
