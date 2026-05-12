package internal

import (
	"context"
	"fmt"
	"net/http"

	policy_manager "github.com/compliance-framework/agent/policy-manager"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
)

type OrgSSO struct {
	Enabled   bool   `json:"enabled"`
	SSOURL    string `json:"sso_url"`
	IDPIssuer string `json:"idp_issuer"`
}

type IPAllowListEntry struct {
	AllowListValue string `json:"allow_list_value"`
	IsActive       bool   `json:"is_active"`
	Name           string `json:"name"`
}

type GithubData struct {
	Settings    *github.Organization `json:"settings"`
	Teams       []*github.Team       `json:"teams"`
	Members     []*github.User       `json:"members"`
	SSO         *OrgSSO              `json:"sso"`
	IPAllowList []IPAllowListEntry   `json:"ip_allow_list"`
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

	steps = append(steps, &proto.Step{
		Title:       "Get Admin Members",
		Description: "Using the client's native APIs, list organization members with the owner/admin role",
		Remarks:     policy_manager.Pointer("More information about data being sent back can be found here: https://docs.github.com/en/rest/orgs/members?apiVersion=2022-11-28#list-organization-members"),
	})

	steps = append(steps, &proto.Step{
		Title:       "Get SSO Configuration",
		Description: "Fetches the SAML SSO configuration for the organization to verify identity provider enforcement",
		Remarks:     policy_manager.Pointer("More information: https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on"),
	})

	steps = append(steps, &proto.Step{
		Title:       "Get IP Allow-List",
		Description: "Fetches the IP allow-list entries for the organization via the GitHub GraphQL API",
		Remarks:     policy_manager.Pointer("More information: https://docs.github.com/en/graphql/reference/objects#ipallowlistentry"),
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

	var allAdminMembers []*github.User
	memberOpt := &github.ListMembersOptions{
		Role:        "admin",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		members, resp, err := df.client.Organizations.ListMembers(ctx, organization, memberOpt)
		if err != nil {
			df.logger.Error("Error getting admin members", "org", organization, "error", err)
			return nil, nil, err
		}

		allAdminMembers = append(allAdminMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		memberOpt.Page = resp.NextPage
	}

	ssoData, err := df.fetchSSO(ctx, organization)
	if err != nil {
		df.logger.Error("Error getting SSO configuration", "org", organization, "error", err)
		return nil, nil, err
	}

	ipAllowList, err := df.fetchIPAllowList(ctx, organization)
	if err != nil {
		df.logger.Error("Error getting IP allow-list", "org", organization, "error", err)
		return nil, nil, err
	}

	return &GithubData{
		Settings:    org,
		Teams:       allTeams,
		Members:     allAdminMembers,
		SSO:         ssoData,
		IPAllowList: ipAllowList,
	}, steps, nil
}

func (df DataFetcher) fetchSSO(ctx context.Context, organization string) (*OrgSSO, error) {
	type samlIdentityProvider struct {
		SSOURL    string `json:"sso_url"`
		Issuer    string `json:"issuer"`
		IDPCertID string `json:"idp_cert_fingerprint"`
	}
	type ssoResponse struct {
		SAMLIdentityProvider *samlIdentityProvider `json:"saml_identity_provider"`
	}

	url := fmt.Sprintf("orgs/%s/sso", organization)
	req, err := df.client.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building SSO request: %w", err)
	}

	var ssoResp ssoResponse
	httpResp, err := df.client.Do(ctx, req, &ssoResp)
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			return &OrgSSO{Enabled: false}, nil
		}
		return nil, fmt.Errorf("fetching SSO config: %w", err)
	}

	if ssoResp.SAMLIdentityProvider == nil {
		return &OrgSSO{Enabled: false}, nil
	}

	return &OrgSSO{
		Enabled:   true,
		SSOURL:    ssoResp.SAMLIdentityProvider.SSOURL,
		IDPIssuer: ssoResp.SAMLIdentityProvider.Issuer,
	}, nil
}

func (df DataFetcher) fetchIPAllowList(ctx context.Context, organization string) ([]IPAllowListEntry, error) {
	type graphqlRequest struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}
	type ipAllowListEntryNode struct {
		AllowListValue string `json:"allowListValue"`
		IsActive       bool   `json:"isActive"`
		Name           string `json:"name"`
	}
	type ipAllowListEdge struct {
		Node ipAllowListEntryNode `json:"node"`
	}
	type ipAllowListConnection struct {
		Edges    []ipAllowListEdge `json:"edges"`
		PageInfo struct {
			HasNextPage bool    `json:"hasNextPage"`
			EndCursor   *string `json:"endCursor"`
		} `json:"pageInfo"`
	}
	type orgNode struct {
		IPAllowListEntries ipAllowListConnection `json:"ipAllowListEntries"`
	}
	type graphqlData struct {
		Organization orgNode `json:"organization"`
	}
	type graphqlResponse struct {
		Data   graphqlData `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	query := `query($login: String!, $after: String) {
		organization(login: $login) {
			ipAllowListEntries(first: 100, after: $after) {
				edges {
					node {
						allowListValue
						isActive
						name
					}
				}
				pageInfo {
					hasNextPage
					endCursor
				}
			}
		}
	}`

	var entries []IPAllowListEntry
	var after *string
	for {
		gqlQuery := graphqlRequest{
			Query: query,
			Variables: map[string]interface{}{
				"login": organization,
				"after": after,
			},
		}

		req, err := df.client.NewRequest(http.MethodPost, "graphql", gqlQuery)
		if err != nil {
			return nil, fmt.Errorf("building IP allow-list GraphQL request: %w", err)
		}

		var gqlResp graphqlResponse
		_, err = df.client.Do(ctx, req, &gqlResp)
		if err != nil {
			return nil, fmt.Errorf("executing IP allow-list GraphQL query: %w", err)
		}

		if len(gqlResp.Errors) > 0 {
			return nil, fmt.Errorf("GraphQL error: %s", gqlResp.Errors[0].Message)
		}

		connection := gqlResp.Data.Organization.IPAllowListEntries
		for _, edge := range connection.Edges {
			entries = append(entries, IPAllowListEntry{
				AllowListValue: edge.Node.AllowListValue,
				IsActive:       edge.Node.IsActive,
				Name:           edge.Node.Name,
			})
		}

		if !connection.PageInfo.HasNextPage {
			break
		}
		if connection.PageInfo.EndCursor == nil {
			return nil, fmt.Errorf("GraphQL response indicated another IP allow-list page without an end cursor")
		}
		after = connection.PageInfo.EndCursor
	}
	return entries, nil
}
