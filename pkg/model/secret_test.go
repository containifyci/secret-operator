package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSecret(t *testing.T) {
	id := "projects/111111111/secrets/SECRETS_NAME"
	value := "top secret"

	secret := NewSecret(id, value)
	assert.Equal(t, id, secret.Id)
	assert.Equal(t, value, secret.Value)
	assert.Equal(t, "SECRETS_NAME", secret.Key)
}

func TestNewSecretResponse(t *testing.T) {
	secrets := map[string]string{
		"projects/111111111/secrets/SECRETS_NAME": "top secret",
	}

	response := NewSecretResponse(secrets)
	assert.Equal(t, 1, len(response.Secrets))
	assert.Equal(t, "top secret", response.Secrets["projects/111111111/secrets/SECRETS_NAME"].Value)
	assert.Equal(t, "SECRETS_NAME", response.Secrets["projects/111111111/secrets/SECRETS_NAME"].Key)
}
