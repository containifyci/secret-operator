package token

import (
	"context"
	"fmt"
	"time"

	"github.com/containifyci/secret-operator/internal"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/golang/protobuf/ptypes/timestamp"
)

// SaveToSecretManager creates or updates the authentication token secret
// in GCP Secret Manager with a 15-minute TTL.
func SaveToSecretManager(ctx context.Context, client *secretmanager.Client, projectID, token string) error {
	secretID := internal.AuthenticationTokenName
	secretName := fmt.Sprintf("projects/%s/secrets/%s", projectID, secretID)

	_, err := client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: secretName})
	if err != nil {
		_, err = client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", projectID),
			SecretId: secretID,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					// Replication: &secretmanagerpb.Replication_Automatic_{
					// 	Automatic: &secretmanagerpb.Replication_Automatic{},
					// },
					Replication: &secretmanagerpb.Replication_UserManaged_{
						UserManaged: &secretmanagerpb.Replication_UserManaged{
							Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
								&secretmanagerpb.Replication_UserManaged_Replica{
									Location: "europe-west3",
								},
							},
						},
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
