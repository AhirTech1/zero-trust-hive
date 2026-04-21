// ─────────────────────────────────────────────────────────────────────────────
// Package auth — JWT Authentication
// ─────────────────────────────────────────────────────────────────────────────
// Provides JWT generation and validation for the Gateway's HTTP API.
// AI agents (LangChain, AutoGPT, Claude) and the Hive CLI authenticate
// by presenting a signed JWT as a Bearer token. The signing secret is
// shared between the Gateway and all authorized clients via HIVE_JWT_SECRET.
//
// Token Structure (Claims):
//
//	sub   — Subject identifier (e.g., "hive-cli", "langchain-agent")
//	iss   — Issuer: always "zero-trust-hive"
//	iat   — Issued-at timestamp
//	exp   — Expiration timestamp (default: 24 hours from issue)
//	scope — Permission scope: "execute", "read", or "admin"
//
// ─────────────────────────────────────────────────────────────────────────────
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ─────────────────────────────────────────────────────────────────────────────
// HiveClaims — custom JWT claims for Zero-Trust Hive
// ─────────────────────────────────────────────────────────────────────────────

// HiveClaims extends the standard JWT claims with Hive-specific fields.
type HiveClaims struct {
	// Scope defines what the token holder is authorized to do.
	// Values: "execute" (dispatch commands), "read" (list agents), "admin" (all).
	Scope string `json:"scope"`

	jwt.RegisteredClaims
}

// ─────────────────────────────────────────────────────────────────────────────
// JWTValidator — validates incoming JWT Bearer tokens
// ─────────────────────────────────────────────────────────────────────────────

// JWTValidator holds the signing secret and validates incoming tokens.
type JWTValidator struct {
	// signingSecret is the HMAC-SHA256 key used to validate token signatures.
	signingSecret []byte
}

// NewJWTValidator creates a validator from the given secret string.
func NewJWTValidator(secret string) *JWTValidator {
	return &JWTValidator{
		signingSecret: []byte(secret),
	}
}

// ValidateToken parses and validates a raw JWT string. Returns the claims
// on success, or an error if the token is expired, malformed, or has an
// invalid signature.
func (v *JWTValidator) ValidateToken(tokenString string) (*HiveClaims, error) {
	claims := &HiveClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC (HS256/HS384/HS512).
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.signingSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return claims, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateToken — creates a signed JWT for a given subject and scope
// ─────────────────────────────────────────────────────────────────────────────
// Used by `hive init` and the CLI to generate tokens for operators and
// AI agents. The default expiration is 24 hours.
// ─────────────────────────────────────────────────────────────────────────────

// GenerateToken creates a new signed JWT with the given subject, scope,
// and a 24-hour expiration window.
func GenerateToken(secret string, subject string, scope string) (string, error) {
	now := time.Now()

	claims := HiveClaims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "zero-trust-hive",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
