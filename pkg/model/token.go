package model

type TokenMetadata struct {
	ServiceName string `json:"serviceName"`
	ClientIP    string `json:"clientIP"`
	Nonce       int64  `json:"nonce"`       // Timestamp in nanoseconds
	RandomValue string `json:"randomValue"` // Random cryptographic value
}
