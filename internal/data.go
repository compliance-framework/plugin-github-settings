package internal

import (
	"context"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
)

type GithubSettings struct {
	Organization *github.Organization `json:"organization"`
}

type DataFetcher struct {
	logger hclog.Logger
	config map[string]string
}

func NewDataFetcher(logger hclog.Logger, config map[string]string) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		config: config,
	}
}

func (df DataFetcher) FetchData() (GithubSettings, []*proto.Step, error) {
	steps := make([]*proto.Step, 0)

	steps = append(steps, &proto.Step{
		Title:       "Configure the Github Client with the Personal Access Token",
		Description: "Using the helper functions within the client, creates a Github API client that can query the API",
	})

	steps = append(steps, &proto.Step{
		Title:       "Query the organization endpoint",
		Description: "Using the client's native APIs, Get all the information from the organization endpoint",
		Remarks:     StringAddressed("More information about data being sent back can be found here: https://docs.github.com/en/rest/orgs/orgs?apiVersion=2022-11-28#get-an-organization"),
	})

	df.logger.Info("Establishing github client and querying APIs")
	client := github.NewClient(nil).WithAuthToken(df.config["api_key"])

	ctx := context.Background()

	org, _, err := client.Organizations.Get(ctx, df.config["organization"])
	if err != nil {
		// TODO handle error sensibly
		df.logger.Error("Error getting organization information", "org", df.config["organization"], "error", err)
	}
	//

	// TODO: Rate limiting check and back off

	return GithubSettings{
		Organization: org,
	}, steps, nil
}
