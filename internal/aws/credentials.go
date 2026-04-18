// Package aws provides dynamic AWS integration for the Zero-Trust Hive CLI.
// This file handles credential discovery — scanning the local environment for
// existing AWS configurations before prompting the user for manual input.
package aws

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// ─────────────────────────────────────────────────────────────────────────────
// CredentialSource — result of the environment scan
// ─────────────────────────────────────────────────────────────────────────────
// This struct tells the caller whether credentials were found and where they
// came from, so the TUI can display an appropriate confirmation prompt.
// ─────────────────────────────────────────────────────────────────────────────

// CredentialSource represents the result of scanning the local environment
// for existing AWS credentials (config files, env vars, profiles).
type CredentialSource struct {
	// Found indicates whether any credential source was detected.
	Found bool

	// Source is a human-readable description of where the credentials came
	// from, e.g. "~/.aws/credentials (profile: default)" or "environment
	// variables (AWS_ACCESS_KEY_ID)".
	Source string

	// Profile is the AWS profile name if one was detected (may be empty).
	Profile string
}

// ─────────────────────────────────────────────────────────────────────────────
// DiscoverCredentials
// ─────────────────────────────────────────────────────────────────────────────
// Checks three locations in priority order:
//   1. AWS_PROFILE environment variable
//   2. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY environment variables
//   3. ~/.aws/credentials file on disk
//
// Returns a CredentialSource describing what was found (if anything).
// ─────────────────────────────────────────────────────────────────────────────

func DiscoverCredentials() CredentialSource {
	// ── Check 1: Named profile via AWS_PROFILE ─────────────────────────
	// If the user has set AWS_PROFILE, they're explicitly telling us which
	// profile to use. This takes highest priority.
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		return CredentialSource{
			Found:   true,
			Source:  fmt.Sprintf("AWS_PROFILE environment variable (profile: %s)", profile),
			Profile: profile,
		}
	}

	// ── Check 2: Inline credentials via environment variables ──────────
	// Some CI/CD pipelines and containerized environments inject credentials
	// directly as env vars rather than using config files.
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		return CredentialSource{
			Found:  true,
			Source: "Environment variables (AWS_ACCESS_KEY_ID)",
		}
	}

	// ── Check 3: Credentials file on disk ──────────────────────────────
	// The standard AWS credentials file lives at ~/.aws/credentials.
	// We check for its existence (not validity) — the SDK will validate
	// the contents when we actually try to use the config.
	homeDir, err := os.UserHomeDir()
	if err == nil {
		credPath := filepath.Join(homeDir, ".aws", "credentials")
		if _, err := os.Stat(credPath); err == nil {
			return CredentialSource{
				Found:   true,
				Source:  fmt.Sprintf("Credentials file (%s)", credPath),
				Profile: "default",
			}
		}
	}

	// ── Nothing found ──────────────────────────────────────────────────
	return CredentialSource{Found: false}
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildDefaultConfig
// ─────────────────────────────────────────────────────────────────────────────
// Loads the AWS SDK configuration using the default credential chain. This
// picks up credentials from env vars, shared config files, IAM roles, etc.
// An optional region override can be applied after initial loading.
// ─────────────────────────────────────────────────────────────────────────────

func BuildDefaultConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{}

	// If a region is specified, override the default.
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return cfg, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildStaticConfig
// ─────────────────────────────────────────────────────────────────────────────
// Creates an AWS SDK configuration from manually-provided access key and
// secret key values. Used when the user opts out of detected credentials
// or when no credentials were found on the system.
// ─────────────────────────────────────────────────────────────────────────────

func BuildStaticConfig(ctx context.Context, accessKey, secretKey, region string) (aws.Config, error) {
	// Create a static credential provider from the user's input.
	staticCreds := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")

	opts := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(staticCreds),
	}

	// Apply region if provided.
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to build static AWS config: %w", err)
	}

	return cfg, nil
}
