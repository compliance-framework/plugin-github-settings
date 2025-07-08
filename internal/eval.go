package internal

import (
	"context"
	"errors"
	"fmt"
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
	evidences      []*proto.Evidence
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{
		ctx:            ctx,
		logger:         logger,
		stepActivities: stepActivities,
		evidences:      make([]*proto.Evidence, 0),
	}
}

func (pe *PolicyEvaluator) GetEvidences() []*proto.Evidence {
	return pe.evidences
}

// Eval is used to run policies against the data you've collected. You could also consider an
// `EvalAndSend` by passing in the `apiHelper` that sends the observations directly to the API.
func (pe *PolicyEvaluator) Eval(organization *github.Organization, policyPaths []string) (proto.ExecutionStatus, error) {
	var accumulatedErrors error

	evalStatus := proto.ExecutionStatus_SUCCESS

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)

	steps := make([]*proto.Step, 0)
	steps = append(steps, &proto.Step{
		Title:       "Compile policy bundle",
		Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
	})
	steps = append(steps, &proto.Step{
		Title:       "Execute policy bundle",
		Description: "Using previously collected JSON-formatted installed OS package data, execute the compiled policies",
	})

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
	components := []*proto.Component{
		{
			Identifier:  "common-components/github-organization",
			Type:        "service",
			Title:       "GitHub Organization",
			Description: "A GitHub Organization is a managed namespace within GitHub that centralizes repositories, teams, access controls, and audit logs for an organization. It supports fine-grained permissions, integrates with identity providers (like SSO), and provides a unified policy and governance layer across all code assets.",
			Purpose:     "To securely manage repositories, teams, and permissions at scale within a centralized administrative structure, supporting governance, policy enforcement, auditability, and organizational collaboration across projects hosted on GitHub.",
		},
		{
			Identifier:  "common-components/version-control",
			Type:        "service",
			Title:       "Version Control",
			Description: "Version control systems track and manage changes to source code and configuration files over time. They provide collaboration, traceability, and the ability to audit or revert code to previous states. Version control enables parallel development workflows and structured release management across software projects.",
			Purpose:     "To maintain a complete and auditable history of code and configuration changes, enable collaboration across distributed teams, and support secure and traceable software development lifecycle (SDLC) practices.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("github-organization/%s", organization.GetLogin()),
			Type:       "github-organization",
			Title:      fmt.Sprintf("Github Organization [%s]", organization.GetName()),
			Props: []*proto.Property{
				{
					Name:  "name",
					Value: organization.GetName(),
				},
				{
					Name:  "path",
					Value: organization.GetLogin(),
				},
			},
			Links: []*proto.Link{
				{
					Href: organization.GetURL(),
					Text: policyManager.Pointer("Organization URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/github-organization",
				},
				{
					Identifier: "common-components/version-control",
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("github-organization/%s", organization.GetLogin()),
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/github-organization",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
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
				"provider":     "github",
				"type":         "organization",
				"organization": organization.GetLogin(),
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)
		evidence, err := processor.GenerateResults(pe.ctx, policyPath, organization)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
		}
	}

	pe.evidences = evidences

	return evalStatus, accumulatedErrors
}
