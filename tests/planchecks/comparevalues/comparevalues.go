// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package comparevalues

import (
	"context"
	"fmt"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

type ComparePlanValues struct {
	ResourceAddress string
	AttributePath   tfjsonpath.Path
	BeforeValue     knownvalue.Check
	AfterValue      knownvalue.Check
}

func (c *ComparePlanValues) CheckPlan(ctx context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	// Find the resource change in the plan
	var rc *tfjson.ResourceChange
	for _, change := range req.Plan.ResourceChanges {
		if change.Address == c.ResourceAddress {
			rc = change
			break
		}
	}

	if rc == nil {
		resp.Error = fmt.Errorf("resource %s not found in plan", c.ResourceAddress)
		return
	}

	// Get the before value
	beforeValue, err := tfjsonpath.Traverse(rc.Change.Before, c.AttributePath)
	if err != nil {
		resp.Error = fmt.Errorf("error traversing before value at path %s: %w", c.AttributePath, err)
		return
	}

	// Check the before value matches expected
	if err := c.BeforeValue.CheckValue(beforeValue); err != nil {
		resp.Error = fmt.Errorf("before value mismatch at path %s: %w", c.AttributePath, err)
		return
	}

	// Get the after value
	afterValue, err := tfjsonpath.Traverse(rc.Change.After, c.AttributePath)
	if err != nil {
		resp.Error = fmt.Errorf("error traversing after value at path %s: %w", c.AttributePath, err)
		return
	}

	// Check the after value matches expected
	if err := c.AfterValue.CheckValue(afterValue); err != nil {
		resp.Error = fmt.Errorf("after value mismatch at path %s: %w", c.AttributePath, err)
		return
	}
}
