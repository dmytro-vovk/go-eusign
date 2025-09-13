package eusign

import (
	"strconv"

	src "github.com/dmytro-vovk/go-eusign/src"
)

type Error struct {
	err src.Error
}

func wrapError(err error) error {
	if e, ok := err.(src.Error); ok && e.Code == src.ErrorNone {
		return nil
	}

	return err
}

func wrapError2[T any](v T, err error) (T, error) {
	if e, ok := err.(src.Error); ok && e.Code == src.ErrorNone {
		return v, nil
	}

	var t T

	return t, err
}

func (err *Error) Error() string {
	return err.err.Message + " (" + strconv.Itoa(err.err.Code) + ")"
}
