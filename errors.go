package eusign

import (
	"strconv"

	"github.com/dmytro-vovk/go-eusign/internal/src"
)

type Error struct {
	err src.Error
}

func wrapError(e src.Error) error {
	if e.Code == src.ErrorNone {
		return nil
	}

	return &Error{e}
}

func wrapError2[T any](v T, e src.Error) (T, error) {
	if e.Code == src.ErrorNone {
		return v, nil
	}

	var t T

	return t, &Error{e}
}

func (err *Error) Error() string {
	return err.err.Message + " (" + strconv.Itoa(err.err.Code) + ")"
}
