package model

import (
	"fmt"
	"path/filepath"
	"strings"
)

type SecretType string

const (
	SecretTypeEnv  SecretType = "env"
	SecretTypeFile SecretType = "file"
)

type (
	SecretResponse struct {
		EnvSecrets  map[string]EnvSecret  `json:"envSecrets"`
		FileSecrets map[string]FileSecret `json:"fileSecrets"`
	}

	EnvSecret struct {
		Id    string `json:"id"`
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	FileSecret struct {
		Id       string `json:"id"`
		Filename string `json:"filename"`
		Value    string `json:"value"`
		Mode     string `json:"mode"`
	}

	SecretMetadata struct {
		Type     SecretType
		Filename string
	}
)

// ParseSecretMetadata extracts secret metadata from GCP secret labels.
// Secrets without a "type" label default to "env" type for backward compatibility.
func ParseSecretMetadata(labels map[string]string) SecretMetadata {
	secretType := SecretTypeEnv
	if t, ok := labels["type"]; ok && t == "file" {
		secretType = SecretTypeFile
	}

	filename := ""
	if f, ok := labels["filename"]; ok {
		filename = f
	}

	return SecretMetadata{
		Type:     secretType,
		Filename: filename,
	}
}

// DetermineFileMode returns the appropriate file mode based on filename patterns.
// Private keys get 0600, certificates get 0644, default is 0600 for security.
func DetermineFileMode(filename string) string {
	lower := strings.ToLower(filename)
	base := strings.ToLower(filepath.Base(filename))

	// Private keys - owner only
	if strings.HasSuffix(lower, ".key") ||
		strings.HasSuffix(lower, ".pem") ||
		strings.Contains(base, "private") {
		return "0600"
	}

	// Certificates - world readable
	if strings.HasSuffix(lower, ".crt") ||
		strings.HasSuffix(lower, ".cert") ||
		strings.HasSuffix(lower, ".ca") {
		return "0644"
	}

	// Secure default
	return "0600"
}

// NewEnvSecret creates a new EnvSecret from an id and value.
// The key is extracted from the last part of the id (e.g., "projects/123/secrets/DB_URL" -> "DB_URL").
func NewEnvSecret(id, value string) EnvSecret {
	parts := strings.Split(id, "/")
	key := parts[len(parts)-1]
	return EnvSecret{
		Id:    id,
		Key:   key,
		Value: value,
	}
}

// NewFileSecret creates a new FileSecret with the specified parameters.
func NewFileSecret(id, value, filename, mode string) FileSecret {
	return FileSecret{
		Id:       id,
		Filename: filename,
		Value:    value,
		Mode:     mode,
	}
}

// NewSecretResponse creates a SecretResponse from env and file secret maps.
func NewSecretResponse(envSecrets map[string]EnvSecret, fileSecrets map[string]FileSecret) SecretResponse {
	if envSecrets == nil {
		envSecrets = make(map[string]EnvSecret)
	}
	if fileSecrets == nil {
		fileSecrets = make(map[string]FileSecret)
	}
	return SecretResponse{
		EnvSecrets:  envSecrets,
		FileSecrets: fileSecrets,
	}
}

// ValidateFilename validates that a filename is safe for use as a secret file path.
// It only allows a single directory level (e.g., "file.txt" or "certs/tls.crt").
// Returns an error for absolute paths, path traversal attempts, or deeply nested paths.
func ValidateFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Reject absolute paths
	if filepath.IsAbs(filename) {
		return fmt.Errorf("absolute paths are not allowed")
	}

	// Clean and resolve the path
	cleaned := filepath.Clean(filename)

	// Check if the cleaned path escapes the current directory
	// by computing relative path from a base directory
	baseDir := "/safe"
	fullPath := filepath.Join(baseDir, cleaned)
	rel, err := filepath.Rel(baseDir, fullPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	// If relative path starts with "..", it escapes the base directory
	if rel != cleaned || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("path traversal not allowed")
	}

	// Count directory depth - only allow one level (dir/file)
	depth := strings.Count(cleaned, string(filepath.Separator))
	if depth > 1 {
		return fmt.Errorf("only one directory level allowed (e.g., 'certs/tls.crt')")
	}

	return nil
}
