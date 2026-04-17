package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestRequireBearerAuth_ValidKey(t *testing.T) {
	handler := RequireBearerAuth("test-api-key", okHandler)
	req := httptest.NewRequest(http.MethodPost, "/generate-token", nil)
	req.Header.Set("Authorization", "Bearer test-api-key")
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireBearerAuth_InvalidKey(t *testing.T) {
	handler := RequireBearerAuth("test-api-key", okHandler)
	req := httptest.NewRequest(http.MethodPost, "/generate-token", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "unauthorized")
}

func TestRequireBearerAuth_MissingHeader(t *testing.T) {
	handler := RequireBearerAuth("test-api-key", okHandler)
	req := httptest.NewRequest(http.MethodPost, "/generate-token", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireBearerAuth_MalformedHeader(t *testing.T) {
	handler := RequireBearerAuth("test-api-key", okHandler)

	tests := []struct {
		name  string
		value string
	}{
		{"Basic auth", "Basic dGVzdDp0ZXN0"},
		{"bare token", "test-api-key"},
		{"lowercase bearer", "bearer test-api-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/generate-token", nil)
			req.Header.Set("Authorization", tt.value)
			rec := httptest.NewRecorder()

			handler(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
}

func TestRequireBearerAuth_EmptyToken(t *testing.T) {
	handler := RequireBearerAuth("test-api-key", okHandler)
	req := httptest.NewRequest(http.MethodPost, "/generate-token", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()

	handler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
