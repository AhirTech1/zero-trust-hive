// Package aws — instances.go dynamically fetches available EC2 instance types
// from the user's AWS account. No hardcoded instance type lists. Budget
// constraints do not apply — every instance type the account allows is shown.
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
// FetchInstanceTypes
// ─────────────────────────────────────────────────────────────────────────────
// Calls ec2:DescribeInstanceTypes to retrieve available instance types. The
// results are paginated (the API returns max 100 per call), so we use a
// paginator to collect everything.
//
// Each option label includes the instance type name, vCPU count, and memory
// in GiB so the user can make an informed selection without leaving the CLI.
//
// Example label: "m5.xlarge — 4 vCPUs, 16.0 GiB RAM"
// ─────────────────────────────────────────────────────────────────────────────

func FetchInstanceTypes(ctx context.Context, cfg aws.Config) ([]huh.Option[string], error) {
	client := ec2.NewFromConfig(cfg)

	// Use the SDK's built-in paginator to handle the multi-page response.
	paginator := ec2.NewDescribeInstanceTypesPaginator(client, &ec2.DescribeInstanceTypesInput{
		MaxResults: aws.Int32(100),
	})

	var options []huh.Option[string]

	// Iterate through all pages of results.
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeInstanceTypes failed: %w", err)
		}

		for _, it := range page.InstanceTypes {
			typeName := string(it.InstanceType)

			// Extract hardware specs for the label.
			var vcpus int32
			var memoryMiB int64

			if it.VCpuInfo != nil && it.VCpuInfo.DefaultVCpus != nil {
				vcpus = *it.VCpuInfo.DefaultVCpus
			}
			if it.MemoryInfo != nil && it.MemoryInfo.SizeInMiB != nil {
				memoryMiB = *it.MemoryInfo.SizeInMiB
			}

			// Convert MiB to GiB for readability.
			memoryGiB := float64(memoryMiB) / 1024.0

			// Format: "m5.xlarge              —  4 vCPUs, 16.0 GiB RAM"
			label := fmt.Sprintf("%-24s —  %d vCPUs, %.1f GiB RAM", typeName, vcpus, memoryGiB)

			options = append(options, huh.NewOption(label, typeName))
		}
	}

	// Sort by instance type name so families are grouped together.
	sort.Slice(options, func(i, j int) bool {
		return options[i].Value < options[j].Value
	})

	return options, nil
}
