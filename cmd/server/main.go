package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/containifyci/secret-operator/internal"
	"github.com/containifyci/secret-operator/pkg/auth"
	"github.com/containifyci/secret-operator/pkg/model"
	"github.com/containifyci/secret-operator/pkg/token"

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
	ctx := context.Background()
	projectID := os.Getenv("GCP_PROJECT_ID")

	apiKey, err := auth.LoadAPIKey(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to load API key: %v", err)
	}

	http.HandleFunc("/retrieve-secrets", RetrieveSecretsHandler)
	http.HandleFunc("/generate-token", auth.RequireBearerAuth(apiKey, GenerateTokenHandler))
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	err = http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func GenerateTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ServiceName string `json:"serviceName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.ServiceName == "" {
		http.Error(w, "serviceName is required", http.StatusBadRequest)
		return
	}

	clientIP := extractClientIP(r)

	tokenStr, _, err := token.Generate(req.ServiceName, clientIP)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		log.Printf("Error generating token: %v", err)
		return
	}

	ctx := r.Context()
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		http.Error(w, "Failed to create Secret Manager client", http.StatusInternalServerError)
		log.Printf("Error creating Secret Manager client: %v", err)
		return
	}
	defer func() {
		err := smClient.Close()
		if err != nil {
			log.Printf("Error closing Secret Manager client: %v", err)
		}
	}()

	projectID := os.Getenv("GCP_PROJECT_ID")
	if err := token.SaveToSecretManager(ctx, smClient, projectID, tokenStr); err != nil {
		http.Error(w, "Failed to save token", http.StatusInternalServerError)
		log.Printf("Error saving token: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": tokenStr}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("Error encoding response: %v", err)
		return
	}
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func RetrieveSecretsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing Authorization token", http.StatusUnauthorized)
		return
	}

	// Validate and retrieve metadata from the token
	metadata, err := validateAndDeleteToken(ctx, client, tokenStr)
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
	envSecrets, fileSecrets, err := getSecretsForService(ctx, client, serviceName)
	if err != nil {
		http.Error(w, "Failed to retrieve secrets", http.StatusInternalServerError)
		log.Printf("Error retrieving secrets: %v", err)
		return
	}

	response := model.NewSecretResponse(envSecrets, fileSecrets)
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		log.Printf("Error encoding response: %v", err)
		return
	}
}

func validateAndDeleteToken(ctx context.Context, client *secretmanager.Client, tokenStr string) (*model.TokenMetadata, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", os.Getenv("GCP_PROJECT_ID"), internal.AuthenticationTokenName)

	// Access the secret version
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("error accessing token secret: %w", err)
	}

	if strings.TrimSpace(string(resp.Payload.Data)) != tokenStr {
		return nil, fmt.Errorf("token mismatch")
	}

	// Parse metadata from the secret
	metadata, err := token.Decode(string(resp.Payload.Data))
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

func getSecretsForService(ctx context.Context, client *secretmanager.Client, serviceName string) (map[string]model.EnvSecret, map[string]model.FileSecret, error) {
	envSecrets := make(map[string]model.EnvSecret)
	fileSecrets := make(map[string]model.FileSecret)
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
			return nil, nil, fmt.Errorf("error listing secrets: %w", err)
		}

		resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: fmt.Sprintf("%s/versions/latest", secret.Name),
		})
		if err != nil {
			log.Printf("Failed to access secret %s: %v", secret.Name, err)
			continue
		}

		value := string(resp.Payload.Data)
		metadata := model.ParseSecretMetadata(secret.Labels)

		if metadata.Type == model.SecretTypeFile {
			// File secret
			filename := metadata.Filename
			if filename == "" {
				// Use secret name as filename if not specified
				parts := strings.Split(secret.Name, "/")
				filename = parts[len(parts)-1]
			}
			mode := model.DetermineFileMode(filename)
			fileSecrets[secret.Name] = model.NewFileSecret(secret.Name, value, filename, mode)
		} else {
			// Env secret (default)
			envSecrets[secret.Name] = model.NewEnvSecret(secret.Name, value)
		}
	}

	return envSecrets, fileSecrets, nil
}
