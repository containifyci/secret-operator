package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/api/iterator"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type TokenMetadata struct {
	ServiceName string `json:"serviceName"`
	ClientIP    string `json:"clientIP"`
	Nonce       int64  `json:"nonce"`       // Timestamp in nanoseconds
	RandomValue string `json:"randomValue"` // Random cryptographic value
}

type SecretResponse struct {
	Secrets map[string]string `json:"secrets"`
}

var predefinedTokenName = "SECRET_OPERATOR_AUTHENTICATION_TOKEN" // Replace with the desired token secret name

func main() {
	http.HandleFunc("/retrieve-secrets", RetrieveSecretsHandler)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func RetrieveSecretsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		http.Error(w, "Failed to create Secret Manager client", http.StatusInternalServerError)
		log.Printf("Error creating Secret Manager client: %v", err)
		return
	}
	defer client.Close()

	// Retrieve token from the request header
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Missing Authorization token", http.StatusUnauthorized)
		return
	}

	// Validate and retrieve metadata from the token
	metadata, err := validateAndDeleteToken(ctx, client, token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		log.Printf("Error validating token: %v", err)
		return
	}

	serviceName := metadata.ServiceName
	if serviceName == "" {
		http.Error(w, "Service name not found in token metadata", http.StatusBadRequest)
		return
	}

	// Retrieve secrets based on the service name
	secrets, err := getSecretsForService(ctx, client, serviceName)
	if err != nil {
		http.Error(w, "Failed to retrieve secrets", http.StatusInternalServerError)
		log.Printf("Error retrieving secrets: %v", err)
		return
	}

	response := SecretResponse{Secrets: secrets}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("Error encoding response: %v", err)
		return
	}
}

func validateAndDeleteToken(ctx context.Context, client *secretmanager.Client, token string) (*TokenMetadata, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", os.Getenv("GCP_PROJECT_ID"), predefinedTokenName)

	// Access the secret version
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("error accessing token secret: %w", err)
	}

	if strings.TrimSpace(string(resp.Payload.Data)) != token {
		return nil, fmt.Errorf("token mismatch")
	}

	// Parse metadata from the secret
	metadata, err := parseMetadataFromToken(string(resp.Payload.Data))
	if err != nil {
		return nil, fmt.Errorf("error parsing token metadata: %w", err)
	}

	// Delete the token after successful validation
	// if err := client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
	// 	Name: fmt.Sprintf("projects/%s/secrets/%s", os.Getenv("GCP_PROJECT_ID"), predefinedTokenName),
	// }); err != nil {
	// 	log.Printf("Failed to delete token secret: %v", err)
	// }

	return &metadata, nil
}

func parseMetadataFromToken(token string) (TokenMetadata, error) {
	var metadata TokenMetadata

	// Decode the Base64 token
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return metadata, fmt.Errorf("failed to decode token: %w", err)
	}

	// Parse JSON metadata
	if err := json.Unmarshal(decoded, &metadata); err != nil {
		return metadata, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return metadata, nil
}

func getSecretsForService(ctx context.Context, client *secretmanager.Client, serviceName string) (map[string]string, error) {
	secrets := make(map[string]string)
	filter := fmt.Sprintf("labels.service=%s", serviceName)

	it := client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", os.Getenv("GCP_PROJECT_ID")),
		Filter: filter,
	})

	fmt.Printf("Listing secrets %s\n", filter)

	for {
		secret, err := it.Next()
		if err == iterator.Done {
			fmt.Printf("Done listing secrets\n")
			break
		}
		if err != nil {
			fmt.Printf("Error listing secrets: %v\n", err)
			return nil, fmt.Errorf("error listing secrets: %w", err)
		}

		// Check if the secret matches the service name (example: use labels or naming conventions)
		// if strings.Contains(secret.Name, serviceName) {
			// Access the secret value
			resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
				Name: fmt.Sprintf("%s/versions/latest", secret.Name),
			})
			if err != nil {
				log.Printf("Failed to access secret %s: %v", secret.Name, err)
				continue
			}
			secrets[secret.Name] = string(resp.Payload.Data)
		// }
	}

	return secrets, nil
}

