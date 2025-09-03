package internal

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

var test_response = `
{
    "settings": {
        "login": "test-org",
        "id": 1234567,
        "node_id": "O_abcdefg",
        "url": "https://api.github.com/orgs/test-org",
        "repos_url": "https://api.github.com/orgs/test-org/repos",
        "events_url": "https://api.github.com/orgs/test-org/events",
        "hooks_url": "https://api.github.com/orgs/test-org/hooks",
        "issues_url": "https://api.github.com/orgs/test-org/issues",
        "members_url": "https://api.github.com/orgs/test-org/members{/member}",
        "public_members_url": "https://api.github.com/orgs/test-org/public_members{/member}",
        "avatar_url": "https://avatars.githubusercontent.com/u/1234567?v=4",
        "description": null,
        "is_verified": false,
        "has_organization_projects": true,
        "has_repository_projects": true,
        "public_repos": 0,
        "public_gists": 0,
        "followers": 0,
        "following": 0,
        "html_url": "https://github.com/test-org",
        "created_at": "2025-04-09T15:36:21Z",
        "updated_at": "2025-04-09T15:38:25Z",
        "archived_at": null,
        "type": "Organization",
        "total_private_repos": 0,
        "owned_private_repos": 0,
        "private_gists": 0,
        "disk_usage": 0,
        "collaborators": 0,
        "billing_email": "test@example.com",
        "default_repository_permission": "read",
        "members_can_create_repositories": true,
        "two_factor_requirement_enabled": false,
        "members_allowed_repository_creation_type": "all",
        "members_can_create_public_repositories": true,
        "members_can_create_private_repositories": true,
        "members_can_create_internal_repositories": false,
        "members_can_create_pages": true,
        "members_can_fork_private_repositories": false,
        "web_commit_signoff_required": false,
        "deploy_keys_enabled_for_repositories": false,
        "members_can_create_public_pages": true,
        "members_can_create_private_pages": true,
        "plan": {
            "name": "free",
            "space": 976562499,
            "private_repos": 10000,
            "filled_seats": 2,
            "seats": 1
        },
        "advanced_security_enabled_for_new_repositories": false,
        "dependabot_alerts_enabled_for_new_repositories": false,
        "dependabot_security_updates_enabled_for_new_repositories": false,
        "dependency_graph_enabled_for_new_repositories": false,
        "secret_scanning_enabled_for_new_repositories": false,
        "secret_scanning_push_protection_enabled_for_new_repositories": false,
        "secret_scanning_push_protection_custom_link_enabled": false,
        "secret_scanning_push_protection_custom_link": null,
        "secret_scanning_validity_checks_enabled": false
    },
    "teams": []
}
`

func TestGithubOrg_EvaluatePolicies(t *testing.T) {
	logger := hclog.NewNullLogger()
	steps := make([]*proto.Activity, 0)

	settings := &GithubData{}
	_ = json.Unmarshal([]byte(test_response), settings)

	ctx := context.TODO()

	evaluator := NewPolicyEvaluator(ctx, logger, steps)
	status, err := evaluator.Eval(settings, []string{"../examples/policies"})

	if status != proto.ExecutionStatus_SUCCESS {
		t.Fail()
	}

	if err != nil {
		t.Fail()
	}

	if len(evaluator.GetEvidences()) < 1 {
		t.Fail()
	}
}
