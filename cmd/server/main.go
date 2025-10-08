package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/containifyci/secret-operator/internal"
	"github.com/containifyci/secret-operator/pkg/model"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/containifyci/go-self-update/pkg/systemd"
	"github.com/containifyci/go-self-update/pkg/updater"
	"google.golang.org/api/iterator"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	fmt.Printf("secret-operator-server %s, commit %s, built at %s\n", version, commit, date)

	command := "run"
	if len(os.Args) >= 2 {
		command = os.Args[1]
	}

	switch command {
	case "update":
		u := updater.NewUpdater(
			"secret-operator-server", "containifyci", "secret-operator", version,
			updater.WithUpdateHook(systemd.SystemdRestartHook("secret-operator-server")),
		)
		updated, err := u.SelfUpdate()
		if err != nil {
			fmt.Printf("Update failed %+v\n", err)
		}
		if updated {
			fmt.Println("Update completed successfully!")
			return
		}
		fmt.Println("Already up-to-date")
	default:
		start()
	}
}

func start() {
	http.HandleFunc("/retrieve-secrets", RetrieveSecretsHandler)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	defer func() {
		err := client.Close()
		if err != nil {
			log.Printf("Error closing Secret Manager client: %v", err)
		}
	}()

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

	response := model.NewSecretResponse(secrets)
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("Error encoding response: %v", err)
		return
	}
}

func validateAndDeleteToken(ctx context.Context, client *secretmanager.Client, token string) (*model.TokenMetadata, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", os.Getenv("GCP_PROJECT_ID"), internal.AuthenticationTokenName)

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

	//Delete the token after successful validation
	if err := client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s", os.Getenv("GCP_PROJECT_ID"), internal.AuthenticationTokenName),
	}); err != nil {
		log.Printf("Failed to delete token secret: %v", err)
	}

	return &metadata, nil
}

func parseMetadataFromToken(token string) (model.TokenMetadata, error) {
	var metadata model.TokenMetadata

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

		resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: fmt.Sprintf("%s/versions/latest", secret.Name),
		})
		if err != nil {
			log.Printf("Failed to access secret %s: %v", secret.Name, err)
			continue
		}
		secrets[secret.Name] = string(resp.Payload.Data)
	}

	return secrets, nil
}
