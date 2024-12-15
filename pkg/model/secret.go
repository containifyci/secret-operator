package model

import "strings"

type (
	SecretResponse struct {
		Secrets map[string]Secret `json:"secrets"`
	}

	Secret struct {
		Id string `json:"id"`
		Key string `json:"key"`
		Value string `json:"value"`
	}
)

func NewSecret(id, value string) Secret {
	parts := strings.Split(id, "/")
	key := parts[len(parts)-1]
	return Secret{
		Id: id,
		Key: key,
		Value: value,
	}
}

func NewSecretResponse(secrets map[string]string) SecretResponse {
	secretMap := make(map[string]Secret)
	for id, value := range secrets {
		secretMap[id] = NewSecret(id, value)
	}
	return SecretResponse{Secrets: secretMap}
}
