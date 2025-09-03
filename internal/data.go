package internal

import (
	"context"

	policy_manager "github.com/compliance-framework/agent/policy-manager"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
)

type GithubData struct {
	Settings *github.Organization `json:"settings"`
	Teams    []*github.Team       `json:"teams"`
}

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

func (df DataFetcher) FetchData(ctx context.Context, organization string) (*GithubData, []*proto.Step, error) {
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

	steps = append(steps, &proto.Step{
		Title:       "Get Teams",
		Description: "Using the client's native APIs, Get all the information from the teams endpoint",
		Remarks:     policy_manager.Pointer("More information about data being sent back can be found here: https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams"),
	})

	org, _, err := df.client.Organizations.Get(ctx, organization)
	if err != nil {
		df.logger.Error("Error getting organization information", "org", organization, "error", err)
		return nil, nil, err
	}

	var allTeams []*github.Team
	paginationOpt := &github.ListOptions{PerPage: 100}

	for {
		teams, resp, err := df.client.Teams.ListTeams(ctx, organization, paginationOpt)
		if err != nil {
			df.logger.Error("Error getting teams information", "org", organization, "error", err)
			return nil, nil, err
		}

		allTeams = append(allTeams, teams...)
		if resp.NextPage == 0 {
			break
		}
		paginationOpt.Page = resp.NextPage
	}

	return &GithubData{
		Settings: org,
		Teams:    allTeams,
	}, steps, nil
}
