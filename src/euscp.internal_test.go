package euscp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCbufsNil(t *testing.T) {
	size, arrays, sizes := cbufs(nil)

	require.Zero(t, size)
	require.Nil(t, arrays)
	require.Nil(t, sizes)
}

func TestCStringsNil(t *testing.T) {
	strings, size := cStrings(nil)

	require.Nil(t, strings)
	require.Zero(t, size)
}
