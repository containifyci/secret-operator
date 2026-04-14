package token

import (
	"testing"

	"github.com/containifyci/secret-operator/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := model.TokenMetadata{
		ServiceName: "my-service",
		ClientIP:    "192.168.1.1",
		Nonce:       1234567890,
		RandomValue: "dGVzdHZhbHVl",
	}

	encoded, err := Encode(original)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded, err := Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDecodeInvalidInput(t *testing.T) {
	_, err := Decode("not-valid-base64!!!")
	assert.Error(t, err)

	_, err = Decode("bm90LWpzb24")
	assert.Error(t, err)
}

func TestGenerateRandomValue(t *testing.T) {
	val1, err := GenerateRandomValue(16)
	require.NoError(t, err)
	assert.NotEmpty(t, val1)

	val2, err := GenerateRandomValue(16)
	require.NoError(t, err)
	assert.NotEqual(t, val1, val2)
}

func TestGenerate(t *testing.T) {
	tokenStr, metadata, err := Generate("test-service", "10.0.0.1")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)
	assert.Equal(t, "test-service", metadata.ServiceName)
	assert.Equal(t, "10.0.0.1", metadata.ClientIP)
	assert.NotZero(t, metadata.Nonce)
	assert.NotEmpty(t, metadata.RandomValue)

	// Verify token decodes back to same metadata
	decoded, err := Decode(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, metadata, decoded)
}
