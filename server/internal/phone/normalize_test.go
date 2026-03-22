package phone

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"+491234567890", "+491234567890", false},
		{"+49 123 456 7890", "+491234567890", false},
		{"00491234567890", "+491234567890", false},
		{"00 49 123 456 7890", "+491234567890", false},
		{"+49 (123) 456-7890", "+491234567890", false},
		{"  +49 123 456 7890  ", "+491234567890", false},
		{"+491111111111", "+491111111111", false},
		{"00491111111111", "+491111111111", false},
		{"+49 11 1111 1111", "+491111111111", false},
		{"", "", true},
		{"abc", "", true},
		{"123", "", true},
		{"+123", "", true}, // too short
		{"+12345", "", true},
		{"+123456", "+123456", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Normalize(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeOrEmpty(t *testing.T) {
	assert.Equal(t, "+491234567890", NormalizeOrEmpty("+49 123 456 7890"))
	assert.Equal(t, "", NormalizeOrEmpty("invalid"))
	assert.Equal(t, "", NormalizeOrEmpty(""))
}
