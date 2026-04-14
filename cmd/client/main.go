package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/containifyci/secret-operator/pkg/model"
	"github.com/containifyci/secret-operator/pkg/token"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/containifyci/go-self-update/pkg/updater"
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
	var envFile, output, host, tokenFlag string
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine = fs
	fs.StringVar(&tokenFlag, "token", "", "The name of the token secret")
	fs.StringVar(&envFile, "envFile", "t.env", "The envFile file to store the secrets in")
	fs.StringVar(&output, "output", ".", "The output directory for secrets")
	fs.StringVar(&host, "host", "https://wg.fr123k.uk:8443/secrets", "The host of the secret operator server to use")
	_ = fs.Parse(os.Args[2:])

	if tokenFlag == "" {
		log.Fatalf("The token arg is required")
	}

	url := fmt.Sprintf("%s/retrieve-secrets", host)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Authorization", tokenFlag)

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

	// Write env secrets to .env file
	if err := writeEnvSecrets(output, envFile, secretResponse.EnvSecrets); err != nil {
		fmt.Printf("Error writing env secrets: %v\n", err)
		os.Exit(1)
	}

	// Write file secrets to individual files
	if err := writeFileSecrets(output, secretResponse.FileSecrets); err != nil {
		fmt.Printf("Error writing file secrets: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Secrets written to %s directory successfully.\n", output)
}

// writeEnvSecrets writes env secrets to a .env file in the output directory.
func writeEnvSecrets(outputDir, envFile string, secrets map[string]model.EnvSecret) error {
	if len(secrets) == 0 {
		return nil
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	envFilePath := filepath.Join(outputDir, envFile)
	f, err := os.OpenFile(envFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create .env file: %w", err)
	}
	defer f.Close()

	for _, secret := range secrets {
		line := fmt.Sprintf("%s=\"%s\"\n", secret.Key, secret.Value)
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("failed to write to .env file: %w", err)
		}
	}

	fmt.Printf("Env secrets written to %s\n", envFilePath)
	return nil
}

// writeFileSecrets writes each file secret to its own file with proper permissions.
func writeFileSecrets(outputDir string, secrets map[string]model.FileSecret) error {
	if len(secrets) == 0 {
		return nil
	}

	for _, secret := range secrets {
		// Validate filename for security
		if err := model.ValidateFilename(secret.Filename); err != nil {
			return fmt.Errorf("invalid filename %q: %w", secret.Filename, err)
		}

		// Build full path
		fullPath := filepath.Join(outputDir, secret.Filename)

		// Ensure parent directory exists
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Parse file mode
		mode, err := parseFileMode(secret.Mode)
		if err != nil {
			return fmt.Errorf("invalid file mode %q: %w", secret.Mode, err)
		}

		// Write file
		if err := os.WriteFile(fullPath, []byte(secret.Value), mode); err != nil {
			return fmt.Errorf("failed to write file %s: %w", fullPath, err)
		}

		fmt.Printf("File secret written to %s (mode %s)\n", fullPath, secret.Mode)
	}

	return nil
}

// parseFileMode parses a string file mode (e.g., "0600") to os.FileMode.
func parseFileMode(modeStr string) (os.FileMode, error) {
	if modeStr == "" {
		return 0600, nil // secure default
	}

	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse mode: %w", err)
	}

	return os.FileMode(mode), nil
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

	tokenStr, _, err := token.Generate(*serviceName, clientIP)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	fmt.Printf("Generated Token: %s\n", tokenStr)

	projectID := os.Getenv("GCP_PROJECT_ID")

	ctx := context.Background()
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create Secret Manager client: %v", err)
	}
	defer func() {
		err := smClient.Close()
		if err != nil {
			fmt.Printf("Error closing Secret Manager client: %v\n", err)
		}
	}()

	if err := token.SaveToSecretManager(ctx, smClient, projectID, tokenStr); err != nil {
		log.Fatalf("Failed to save token to Secret Manager: %v", err)
	}
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
