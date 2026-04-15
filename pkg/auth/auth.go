package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"

	"github.com/containifyci/secret-operator/internal"
)

// LoadAPIKey fetches the API key from GCP Secret Manager.
func LoadAPIKey(ctx context.Context, projectID string) (string, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create Secret Manager client: %w", err)
	}
	defer client.Close()

	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, internal.APIKeySecretName)
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to access API key secret: %w", err)
	}

	key := strings.TrimSpace(string(resp.Payload.Data))
	if key == "" {
		return "", fmt.Errorf("API key secret is empty")
	}

	return key, nil
}

// RequireBearerAuth wraps an http.HandlerFunc with Bearer token authentication.
func RequireBearerAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if !strings.HasPrefix(authHeader, "Bearer ") {
			unauthorized(w, r)
			return
		}

		token := authHeader[len("Bearer "):]
		if len(token) == 0 || subtle.ConstantTimeCompare([]byte(token), []byte(apiKey)) != 1 {
			unauthorized(w, r)
			return
		}

		next(w, r)
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	log.Printf("Unauthorized request to %s from %s", r.URL.Path, r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}
