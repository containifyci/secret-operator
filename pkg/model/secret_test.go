package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSecretMetadata(t *testing.T) {
	tests := []struct {
		name           string
		labels         map[string]string
		expectedType   SecretType
		expectedFile   string
	}{
		{
			name:           "empty labels defaults to env",
			labels:         map[string]string{},
			expectedType:   SecretTypeEnv,
			expectedFile:   "",
		},
		{
			name:           "nil labels defaults to env",
			labels:         nil,
			expectedType:   SecretTypeEnv,
			expectedFile:   "",
		},
		{
			name:           "explicit env type",
			labels:         map[string]string{"type": "env"},
			expectedType:   SecretTypeEnv,
			expectedFile:   "",
		},
		{
			name:           "file type with filename",
			labels:         map[string]string{"type": "file", "filename": "certs/tls.crt"},
			expectedType:   SecretTypeFile,
			expectedFile:   "certs/tls.crt",
		},
		{
			name:           "file type without filename",
			labels:         map[string]string{"type": "file"},
			expectedType:   SecretTypeFile,
			expectedFile:   "",
		},
		{
			name:           "unknown type defaults to env",
			labels:         map[string]string{"type": "unknown"},
			expectedType:   SecretTypeEnv,
			expectedFile:   "",
		},
		{
			name:           "service label only (backward compat)",
			labels:         map[string]string{"service": "my-service"},
			expectedType:   SecretTypeEnv,
			expectedFile:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := ParseSecretMetadata(tt.labels)
			assert.Equal(t, tt.expectedType, metadata.Type)
			assert.Equal(t, tt.expectedFile, metadata.Filename)
		})
	}
}

func TestDetermineFileMode(t *testing.T) {
	tests := []struct {
		filename     string
		expectedMode string
	}{
		// Private keys - 0600
		{"tls.key", "0600"},
		{"server.key", "0600"},
		{"certs/tls.key", "0600"},
		{"private.pem", "0600"},
		{"server.pem", "0600"},
		{"private-key.txt", "0600"},
		{"my-private-cert", "0600"},

		// Certificates - 0644
		{"tls.crt", "0644"},
		{"server.crt", "0644"},
		{"certs/tls.crt", "0644"},
		{"ca.cert", "0644"},
		{"root.ca", "0644"},

		// Default - 0600 (secure default)
		{"config.json", "0600"},
		{"data.txt", "0600"},
		{"unknown", "0600"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			mode := DetermineFileMode(tt.filename)
			assert.Equal(t, tt.expectedMode, mode)
		})
	}
}

func TestNewEnvSecret(t *testing.T) {
	id := "projects/111111111/secrets/SECRETS_NAME"
	value := "top secret"

	secret := NewEnvSecret(id, value)
	assert.Equal(t, id, secret.Id)
	assert.Equal(t, value, secret.Value)
	assert.Equal(t, "SECRETS_NAME", secret.Key)
}

func TestNewFileSecret(t *testing.T) {
	id := "projects/111111111/secrets/tls-cert"
	value := "-----BEGIN CERTIFICATE-----"
	filename := "certs/tls.crt"
	mode := "0644"

	secret := NewFileSecret(id, value, filename, mode)
	assert.Equal(t, id, secret.Id)
	assert.Equal(t, value, secret.Value)
	assert.Equal(t, filename, secret.Filename)
	assert.Equal(t, mode, secret.Mode)
}

func TestNewSecretResponse(t *testing.T) {
	envSecrets := map[string]EnvSecret{
		"projects/111111111/secrets/DB_URL": NewEnvSecret("projects/111111111/secrets/DB_URL", "postgres://localhost"),
	}
	fileSecrets := map[string]FileSecret{
		"projects/111111111/secrets/tls-cert": NewFileSecret("projects/111111111/secrets/tls-cert", "cert-data", "certs/tls.crt", "0644"),
	}

	response := NewSecretResponse(envSecrets, fileSecrets)

	assert.Equal(t, 1, len(response.EnvSecrets))
	assert.Equal(t, "postgres://localhost", response.EnvSecrets["projects/111111111/secrets/DB_URL"].Value)
	assert.Equal(t, "DB_URL", response.EnvSecrets["projects/111111111/secrets/DB_URL"].Key)

	assert.Equal(t, 1, len(response.FileSecrets))
	assert.Equal(t, "cert-data", response.FileSecrets["projects/111111111/secrets/tls-cert"].Value)
	assert.Equal(t, "certs/tls.crt", response.FileSecrets["projects/111111111/secrets/tls-cert"].Filename)
}

func TestNewSecretResponseWithNilMaps(t *testing.T) {
	response := NewSecretResponse(nil, nil)

	assert.NotNil(t, response.EnvSecrets)
	assert.NotNil(t, response.FileSecrets)
	assert.Equal(t, 0, len(response.EnvSecrets))
	assert.Equal(t, 0, len(response.FileSecrets))
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		wantError bool
	}{
		// Valid cases
		{"simple filename", "tls.crt", false},
		{"single dir level", "certs/tls.crt", false},
		{"single dir level key", "certs/tls.key", false},
		{"config file", "config.json", false},

		// Invalid: empty
		{"empty filename", "", true},

		// Invalid: absolute paths
		{"absolute path unix", "/etc/passwd", true},
		{"absolute path with file", "/certs/tls.crt", true},

		// Invalid: path traversal
		{"parent directory", "..", true},
		{"parent with file", "../passwd", true},
		{"parent in middle", "certs/../../../etc/passwd", true},
		{"double parent", "../../etc/passwd", true},
		{"hidden parent traversal", "certs/../../etc/passwd", true},

		// Invalid: too many directory levels
		{"two dir levels", "a/b/c.txt", true},
		{"three dir levels", "a/b/c/d.txt", true},
		{"deep nesting", "var/log/app/secrets/tls.crt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilename(tt.filename)
			if tt.wantError {
				assert.Error(t, err, "expected error for filename: %s", tt.filename)
			} else {
				assert.NoError(t, err, "unexpected error for filename: %s", tt.filename)
			}
		})
	}
}
