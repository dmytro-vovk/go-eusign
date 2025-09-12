package eusign

import (
	"io"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

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

func cp1251ToUTF8(s string) string {
	r := transform.NewReader(strings.NewReader(s), charmap.Windows1251.NewDecoder())
	b, err := io.ReadAll(r)
	if err != nil {
		return s
	}

	return string(b)
}
