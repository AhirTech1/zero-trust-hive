// Package aws — regions.go dynamically fetches all available AWS regions
// using the EC2 DescribeRegions API. No hardcoded region lists.
package aws

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/charmbracelet/huh"
)

// ─────────────────────────────────────────────────────────────────────────────
// FetchRegions
// ─────────────────────────────────────────────────────────────────────────────
// Calls ec2:DescribeRegions to retrieve every region the caller's AWS account
// has access to. Returns a sorted slice of huh.Option values ready to be
// plugged directly into a huh.Select dropdown.
//
// The label for each option shows the region name and its endpoint for
// disambiguation (e.g., "us-east-1 (ec2.us-east-1.amazonaws.com)").
// ─────────────────────────────────────────────────────────────────────────────

func FetchRegions(ctx context.Context, cfg aws.Config) ([]huh.Option[string], error) {
	// Create an EC2 client. We use a default region for this initial call
	// since DescribeRegions works from any region.
	client := ec2.NewFromConfig(cfg)

	// Call DescribeRegions with AllRegions=true to include opt-in regions.
	input := &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
	}

	result, err := client.DescribeRegions(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("DescribeRegions failed: %w", err)
	}

	// Build the options slice from the API response.
	options := make([]huh.Option[string], 0, len(result.Regions))
	for _, region := range result.Regions {
		name := aws.ToString(region.RegionName)
		endpoint := aws.ToString(region.Endpoint)

		// Format: "us-east-1  —  ec2.us-east-1.amazonaws.com"
		label := fmt.Sprintf("%-20s —  %s", name, endpoint)
		options = append(options, huh.NewOption(label, name))
	}

	// Sort alphabetically by region name for easy scanning.
	sort.Slice(options, func(i, j int) bool {
		return options[i].Value < options[j].Value
	})

	return options, nil
}
