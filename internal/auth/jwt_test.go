package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidateToken(t *testing.T) {
	secret := "test-secret-key-32-bytes-long!!"
	token, err := GenerateToken(secret, "test-agent", "execute")
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	validator := NewJWTValidator(secret)
	claims, err := validator.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Subject != "test-agent" {
		t.Errorf("subject = %q, want %q", claims.Subject, "test-agent")
	}
	if claims.Scope != "execute" {
		t.Errorf("scope = %q, want %q", claims.Scope, "execute")
	}
	if claims.Issuer != "zero-trust-hive" {
		t.Errorf("issuer = %q, want %q", claims.Issuer, "zero-trust-hive")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	token, _ := GenerateToken("secret-a", "agent", "execute")
	validator := NewJWTValidator("secret-b")
	_, err := validator.ValidateToken(token)
	if err == nil {
		t.Fatal("expected error with wrong secret, got nil")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	secret := "test-secret-key-32-bytes-long!!"
	now := time.Now()

	claims := HiveClaims{
		Scope: "execute",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "agent",
			Issuer:    "zero-trust-hive",
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)),
		},
	}
	// Build token manually — we need a package-level import for jwt.
	// We use the jwt package directly.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))

	validator := NewJWTValidator(secret)
	_, err := validator.ValidateToken(tokenString)
	if err == nil {
		t.Fatal("expected error with expired token, got nil")
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	validator := NewJWTValidator("secret")
	_, err := validator.ValidateToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error with invalid token, got nil")
	}
}

func TestValidateToken_WrongAlgorithm(t *testing.T) {
	// Create a token signed with "none" algorithm
	token := jwt.New(jwt.SigningMethodNone)
	claims := jwt.MapClaims{
		"sub": "agent",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token.Claims = claims
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	validator := NewJWTValidator("secret")
	_, err := validator.ValidateToken(tokenString)
	if err == nil {
		t.Fatal("expected error with unsigned token, got nil")
	}
}