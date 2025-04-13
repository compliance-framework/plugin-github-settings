package internal

import (
	"context"
	"errors"
	"github.com/google/go-github/v71/github"
	"slices"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
	observations   []*proto.Observation
	findings       []*proto.Finding
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{
		ctx:            ctx,
		logger:         logger,
		stepActivities: stepActivities,
		observations:   make([]*proto.Observation, 0),
		findings:       make([]*proto.Finding, 0),
	}
}

func (pe *PolicyEvaluator) GetObservations() []*proto.Observation {
	return pe.observations
}

func (pe *PolicyEvaluator) GetFindings() []*proto.Finding {
	return pe.findings
}

// Eval is used to run policies against the data you've collected. You could also consider an
// `EvalAndSend` by passing in the `apiHelper` that sends the observations directly to the API.
func (pe *PolicyEvaluator) Eval(organization *github.Organization, policyPaths []string) (proto.ExecutionStatus, error) {
	var accumulatedErrors error

	evalStatus := proto.ExecutionStatus_SUCCESS

	activities := make([]*proto.Activity, 0)
	findings := make([]*proto.Finding, 0)
	observations := make([]*proto.Observation, 0)

	steps := make([]*proto.Step, 0)
	steps = append(steps, &proto.Step{
		Title:       "Compile policy bundle",
		Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
	})
	steps = append(steps, &proto.Step{
		Title:       "Execute policy bundle",
		Description: "Using previously collected JSON-formatted installed OS package data, execute the compiled policies",
	})

	subjects := []*proto.SubjectReference{
		{
			Type: "software-organization",
			Attributes: map[string]string{
				"provider":          "github",
				"type":              "organization",
				"organization-name": organization.GetName(),
				"organization-path": organization.GetLogin(),
			},
			Title: policyManager.Pointer("Software Organization"),
			Props: []*proto.Property{
				{
					Name:  "organization",
					Value: organization.GetName(),
				},
			},
			Links: []*proto.Link{
				{
					Href: organization.GetURL(),
					Text: policyManager.Pointer("Organization URL"),
				},
			},
		},
	}
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
				},
			},
			Props: nil,
		},
		{
			Title: "Continuous Compliance Framework - Github Settings plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-github-settings",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework' Github Settings Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.ComponentReference{
		{
			Identifier: "common-components/github-organization",
		},
		{
			Identifier: "common-components/version-control",
		},
	}

	activities = append(activities, &proto.Activity{
		Title:       "Compile Results",
		Description: "Using the output from policy execution, compile the resulting output to Observations and Findings, marking any violations, risks, and other OSCAL-familiar data",
		Steps:       steps,
	})

	for _, policyPath := range policyPaths {
		// Explicitly reset steps to make things readable
		processor := policyManager.NewPolicyProcessor(
			pe.logger,
			map[string]string{
				"provider":          "github",
				"type":              "organization",
				"organization-name": organization.GetName(),
				"_policy_path":      policyPath,
			},
			subjects,
			components,
			actors,
			activities,
		)
		obs, finds, err := processor.GenerateResults(pe.ctx, policyPath, organization)
		observations = slices.Concat(observations, obs)
		findings = slices.Concat(findings, finds)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	pe.observations = observations
	pe.findings = findings

	return evalStatus, accumulatedErrors
}
