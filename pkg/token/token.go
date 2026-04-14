package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/containifyci/secret-operator/pkg/model"
)

// GenerateRandomValue generates a cryptographically random base64url-encoded string.
func GenerateRandomValue(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Encode marshals TokenMetadata to JSON and base64url-encodes it.
func Encode(metadata model.TokenMetadata) (string, error) {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(metadataBytes), nil
}

// Decode base64url-decodes and JSON-unmarshals a token string into TokenMetadata.
func Decode(tokenStr string) (model.TokenMetadata, error) {
	var metadata model.TokenMetadata

	decoded, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return metadata, fmt.Errorf("failed to decode token: %w", err)
	}

	if err := json.Unmarshal(decoded, &metadata); err != nil {
		return metadata, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return metadata, nil
}

// Generate builds a TokenMetadata from the given service name and client IP,
// populates Nonce and RandomValue, encodes it, and returns the token string
// along with the populated metadata.
func Generate(serviceName, clientIP string) (string, model.TokenMetadata, error) {
	randomValue, err := GenerateRandomValue(16)
	if err != nil {
		return "", model.TokenMetadata{}, fmt.Errorf("failed to generate random value: %w", err)
	}

	metadata := model.TokenMetadata{
		ServiceName: serviceName,
		ClientIP:    clientIP,
		Nonce:       time.Now().UnixNano(),
		RandomValue: randomValue,
	}

	tokenStr, err := Encode(metadata)
	if err != nil {
		return "", model.TokenMetadata{}, err
	}

	return tokenStr, metadata, nil
}
