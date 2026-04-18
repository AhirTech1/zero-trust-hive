// Package aws — amis.go dynamically fetches available Amazon Machine Images
// (AMIs) from the selected region. Filters for recent, HVM-based, x86_64
// images owned by Amazon to provide a curated but fully dynamic list.
package aws

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/charmbracelet/huh"
)

// ─────────────────────────────────────────────────────────────────────────────
// FetchAMIs
// ─────────────────────────────────────────────────────────────────────────────
// Calls ec2:DescribeImages to retrieve Amazon-owned, HVM, x86_64 AMIs
// available in the currently configured region. The results are filtered
// server-side to reduce payload size and sorted by name for easy browsing.
//
// Each option label shows: "Amazon Linux 2023 AMI (ami-0abcdef1234567890)"
// so the user sees both the human-readable name and the AMI ID.
// ─────────────────────────────────────────────────────────────────────────────

func FetchAMIs(ctx context.Context, cfg aws.Config) ([]huh.Option[string], error) {
	client := ec2.NewFromConfig(cfg)

	// ── Server-side filters to get a manageable, relevant set ──────────
	// - owner-alias = "amazon" → only Amazon-published images
	// - architecture = "x86_64" → standard architecture
	// - virtualization-type = "hvm" → modern virtualization
	// - state = "available" → only images ready for launch
	// - root-device-type = "ebs" → EBS-backed (standard)
	input := &ec2.DescribeImagesInput{
		Owners: []string{"amazon"},
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("architecture"),
				Values: []string{"x86_64"},
			},
			{
				Name:   aws.String("virtualization-type"),
				Values: []string{"hvm"},
			},
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
			{
				Name:   aws.String("root-device-type"),
				Values: []string{"ebs"},
			},
			{
				// Filter for Amazon Linux, Ubuntu, and Windows AMIs by name pattern.
				// This narrows thousands of images down to the most commonly used ones.
				Name: aws.String("name"),
				Values: []string{
					"amzn2-ami-hvm-*",            // Amazon Linux 2
					"al2023-ami-*",               // Amazon Linux 2023
					"ubuntu/images/hvm-ssd/*",    // Ubuntu
					"Windows_Server-*-English-*", // Windows Server
				},
			},
		},
		MaxResults: aws.Int32(50), // Limit to a reasonable number for TUI display.
	}

	result, err := client.DescribeImages(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("DescribeImages failed: %w", err)
	}

	// Build options from the response.
	options := make([]huh.Option[string], 0, len(result.Images))
	for _, image := range result.Images {
		amiID := aws.ToString(image.ImageId)
		name := aws.ToString(image.Name)

		// Use the name if available, otherwise fall back to description.
		displayName := name
		if displayName == "" {
			displayName = aws.ToString(image.Description)
		}
		if displayName == "" {
			displayName = "Unnamed AMI"
		}

		// Truncate very long names for TUI readability.
		if len(displayName) > 60 {
			displayName = displayName[:57] + "..."
		}

		// Format: "Amazon Linux 2023 AMI 2023.x  (ami-0abcdef1234567890)"
		label := fmt.Sprintf("%s  (%s)", displayName, amiID)
		options = append(options, huh.NewOption(label, amiID))
	}

	// Sort alphabetically by the display label.
	sort.Slice(options, func(i, j int) bool {
		return options[i].Key < options[j].Key
	})

	return options, nil
}
