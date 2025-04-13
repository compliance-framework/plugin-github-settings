package internal

import (
	"context"
	policy_manager "github.com/compliance-framework/agent/policy-manager"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
)

type DataFetcher struct {
	logger hclog.Logger
	client *github.Client
}

func NewDataFetcher(logger hclog.Logger, client *github.Client) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		client: client,
	}
}

func (df DataFetcher) FetchData(ctx context.Context, organization string) (*github.Organization, []*proto.Step, error) {
	steps := make([]*proto.Step, 0)

	steps = append(steps, &proto.Step{
		Title:       "Configure the Github Client with the Personal Access Token",
		Description: "Using the helper functions within the client, creates a Github API client that can query the API",
	})

	steps = append(steps, &proto.Step{
		Title:       "Query the organization endpoint",
		Description: "Using the client's native APIs, Get all the information from the organization endpoint",
		Remarks:     policy_manager.Pointer("More information about data being sent back can be found here: https://docs.github.com/en/rest/orgs/orgs?apiVersion=2022-11-28#get-an-organization"),
	})

	org, _, err := df.client.Organizations.Get(ctx, organization)
	if err != nil {
		df.logger.Error("Error getting organization information", "org", organization, "error", err)
		return nil, nil, err
	}

	return org, steps, nil
}
