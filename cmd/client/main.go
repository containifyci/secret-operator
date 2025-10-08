package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/containifyci/secret-operator/internal"
	"github.com/containifyci/secret-operator/pkg/model"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/containifyci/go-self-update/pkg/updater"
	"github.com/golang/protobuf/ptypes/timestamp"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	fmt.Printf("secret-operator-client %s, commit %s, built at %s\n", version, commit, date)

	command := "generate"
	if len(os.Args) >= 2 {
		command = os.Args[1]
	}

	switch command {
	case "update":
		u := updater.NewUpdater(
			"secret-operator-client", "containifyci", "secret-operator", version,
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
	case "fetch":
		fetch()
	case "generate":
		fallthrough
	default:
		generate()
	}
}

func fetch() {
	var envfile, host, token string
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine = fs
	fs.StringVar(&token, "token", "", "The name of the token secret")
	fs.StringVar(&envfile, "envfile", ".env", "THe env file to write the secrets to")
	fs.StringVar(&host, "host", "https://wg.fr123k.uk:8443", "The host of the secret operator server to use")
	_ = fs.Parse(os.Args[2:])

	if token == "" {
		log.Fatalf("The token arg is required")
	}

	url := fmt.Sprintf("%s/secrets/retrieve-secrets", host)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Authorization", token)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Non-OK HTTP status: %s\n", resp.Status)
		os.Exit(1)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		os.Exit(1)
	}

	var secretResponse model.SecretResponse
	if err := json.Unmarshal(body, &secretResponse); err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	envFile, err := os.Create(envfile)
	if err != nil {
		fmt.Printf("Error creating .env file: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		err := envFile.Close()
		if err != nil {
			fmt.Printf("Error closing .env file: %v\n", err)
		}
	}()

	for _, secret := range secretResponse.Secrets {
		line := fmt.Sprintf("%s=\"%s\"\n", secret.Key, secret.Value)
		if _, err := envFile.WriteString(line); err != nil {
			fmt.Printf("Error writing to .env file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Secrets written to %s file successfully. \n", envfile)
}

func generate() {
	serviceName := flag.String("serviceName", "", "The name of the service")
	flag.Parse()

	if *serviceName == "" {
		log.Fatalf("The --serviceName flag is required")
	}

	clientIP, err := getClientIP()
	if err != nil {
		log.Fatalf("Failed to retrieve client IP: %v", err)
	}

	tokenMetadata := model.TokenMetadata{
		ServiceName: *serviceName,
		ClientIP:    clientIP,
		Nonce:       time.Now().UnixNano(),
	}
	tokenMetadata.RandomValue, err = generateRandomValue(16) // Generate a random 16-byte value
	if err != nil {
		log.Fatalf("Failed to generate random value: %v", err)
	}

	token, err := generateToken(tokenMetadata)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	fmt.Printf("Generated Token: %s\n", token)

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
	defer func() {
		err := client.Close()
		if err != nil {
			fmt.Printf("Error closing Secret Manager client: %v\n", err)
		}
	}()

	secretID := internal.AuthenticationTokenName
	secretName := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)
	_, err = client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: secretName})
	if err != nil {
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

func generateRandomValue(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func generateToken(metadata model.TokenMetadata) (string, error) {
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(metadataBytes), nil
}
