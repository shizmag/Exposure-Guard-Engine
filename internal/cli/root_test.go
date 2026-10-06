package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevels(t *testing.T) {
	SetLogLevel("debug")
	assert.Equal(t, LogLevelDebug, currentLogLevel)

	SetLogLevel("info")
	assert.Equal(t, LogLevelInfo, currentLogLevel)

	SetLogLevel("warn")
	assert.Equal(t, LogLevelWarn, currentLogLevel)

	SetLogLevel("warning")
	assert.Equal(t, LogLevelWarn, currentLogLevel)

	SetLogLevel("error")
	assert.Equal(t, LogLevelError, currentLogLevel)

	SetLogLevel("unknown")
	assert.Equal(t, LogLevelInfo, currentLogLevel)
}

func TestExitCodeError(t *testing.T) {
	err := &ExitCodeError{Code: 42}
	assert.Equal(t, "exit code 42", err.Error())
	assert.Nil(t, err.Unwrap())
}
