package internal

import (
	"context"
	"errors"
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
func (pe *PolicyEvaluator) Eval(data GithubSettings, policyPaths []string) (proto.ExecutionStatus, error) {
	var accumulatedErrors error

	evalStatus := proto.ExecutionStatus_SUCCESS

	// Cast the interface{} back to a github Organization so we can use all the helper functions that exist underneath
	organization := data.Organization
	org_name := organization.GetLogin()

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

	subjectAttributeMap := map[string]string{
		"type":          "software-organization",
		"name":          org_name,
		"org-url":       organization.GetURL(),
		"billing-email": organization.GetBillingEmail(),
	}
	subjects := []*proto.SubjectReference{
		{
			Type:       "software-organization",
			Attributes: subjectAttributeMap,
			Title:      StringAddressed("Github Organization "),
			Remarks:    StringAddressed("The Github organization that is being audited"),
			Props: []*proto.Property{
				{
					Name:    "organization-name",
					Value:   org_name,
					Remarks: StringAddressed("The name of the Github Organization"),
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
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework"),
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
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework' Github Settings Plugin"),
				},
			},
			Props: nil,
		},
	}
	components := []*proto.ComponentReference{
		{
			Identifier: "common-components/template",
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
				"organization-name": org_name,
				"_policy_path":      policyPath,
			},
			subjects,
			components,
			actors,
			activities,
		)
		obs, finds, err := processor.GenerateResults(pe.ctx, policyPath, data)
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
