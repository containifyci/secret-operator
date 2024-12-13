package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang/protobuf/ptypes/timestamp"
)

var predefinedTokenName = "SECRET_OPERATOR_AUTHENTICATION_TOKEN" // Replace with the desired token secret name

// TokenMetadata represents the structure of metadata encoded in the token.
type TokenMetadata struct {
	ServiceName string `json:"serviceName"`
	ClientIP    string `json:"clientIP"`
	Nonce       int64  `json:"nonce"`       // Timestamp in nanoseconds
	RandomValue string `json:"randomValue"` // Random cryptographic value
}

func main() {
	// Define CLI flags
	serviceName := flag.String("serviceName", "", "The name of the service")
	flag.Parse()

	if *serviceName == "" {
		log.Fatalf("The --serviceName flag is required")
	}

	// Retrieve the client IP
	clientIP, err := getClientIP()
	if err != nil {
		log.Fatalf("Failed to retrieve client IP: %v", err)
	}

	// Generate token
	tokenMetadata := TokenMetadata{
		ServiceName: *serviceName,
		ClientIP:    clientIP,
		Nonce:       time.Now().UnixNano(), // Add a high-resolution timestamp
	}
	tokenMetadata.RandomValue, err = generateRandomValue(16) // Generate a random 16-byte value
	if err != nil {
		log.Fatalf("Failed to generate random value: %v", err)
	}

	token, err := generateToken(tokenMetadata)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	// Output the token
	fmt.Printf("Generated Token: %s\n", token)

	// Save the token to Secret Manager
	projectID := os.Getenv("GCP_PROJECT_ID")
	if err := saveTokenToSecretManager(projectID, token); err != nil {
		log.Fatalf("Failed to save token to Secret Manager: %v", err)
	}

}

func saveTokenToSecretManager(projectID, token string) error {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	// Define the secret name
	secretID := predefinedTokenName

	// Check if the secret exists
	secretName := fmt.Sprintf("projects/%s/secrets/%s", projectID, predefinedTokenName)
	_, err = client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: secretName})
	if err != nil {
		// Create the secret if it doesn't exist
		_, err = client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", projectID),
			SecretId: secretID,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{
						Automatic: &secretmanagerpb.Replication_Automatic{},
					},
				},
				Expiration: &secretmanagerpb.Secret_ExpireTime{
					ExpireTime: &timestamp.Timestamp{
						Seconds: time.Now().Add(15 * time.Minute).Unix(),
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	}

	// Add the token as a secret version
	_, err = client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(token),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}

	return nil
}

// TODO return all non localhost ip addresses
func getClientIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("could not determine client IP")
}

// generateRandomValue creates a cryptographically secure random value of the specified length.
func generateRandomValue(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateToken encodes the token metadata as a Base64 JSON string.
func generateToken(metadata TokenMetadata) (string, error) {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(metadataBytes), nil
}