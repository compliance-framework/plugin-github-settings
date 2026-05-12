package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/rego"
)

func testGithubClient(t *testing.T, handler http.Handler) (*github.Client, func()) {
	t.Helper()

	server := httptest.NewServer(handler)
	client := github.NewClient(server.Client())

	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	client.BaseURL = baseURL

	return client, server.Close
}

func TestFetchDataReturnsErrorWhenOrganizationFetchFails(t *testing.T) {
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "organization unavailable", http.StatusInternalServerError)
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	data, steps, err := fetcher.FetchData(context.Background(), "acme", false)
	if err == nil {
		t.Fatal("FetchData should return an error when the required organization endpoint fails")
	}
	if data != nil {
		t.Fatalf("data = %#v, want nil", data)
	}
	if steps != nil {
		t.Fatalf("steps = %#v, want nil", steps)
	}
}

func TestFetchDataSkipsOptionalCollectionErrors(t *testing.T) {
	optionalRequests := make(map[string]int)
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"acme","name":"Acme","url":"https://api.github.com/orgs/acme"}`))
		case "/orgs/acme/teams", "/orgs/acme/members", "/orgs/acme/sso", "/graphql":
			optionalRequests[r.URL.Path]++
			http.Error(w, "optional data unavailable", http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	data, steps, err := fetcher.FetchData(context.Background(), "acme", true)
	if err == nil {
		t.Fatal("FetchData should return accumulated errors when optional collections fail")
	}
	if data == nil {
		t.Fatal("data should be returned when only optional collection fails")
	}
	if data.Settings.GetLogin() != "acme" {
		t.Fatalf("organization login = %q, want acme", data.Settings.GetLogin())
	}
	if len(data.Teams) != 0 {
		t.Fatalf("len(Teams) = %d, want 0", len(data.Teams))
	}
	if len(data.Members) != 0 {
		t.Fatalf("len(Members) = %d, want 0", len(data.Members))
	}
	if data.SSO != nil {
		t.Fatalf("SSO = %#v, want nil", data.SSO)
	}
	if data.IPAllowList == nil {
		t.Fatal("IPAllowList pointer should be set")
	}
	if *data.IPAllowList != nil {
		t.Fatalf("IPAllowList = %#v, want nil slice for skipped collection", *data.IPAllowList)
	}
	if len(steps) == 0 {
		t.Fatal("steps should still describe the collection activity")
	}
	for _, path := range []string{"/orgs/acme/teams", "/orgs/acme/members", "/orgs/acme/sso", "/graphql"} {
		if optionalRequests[path] != 1 {
			t.Fatalf("%s requests = %d, want 1", path, optionalRequests[path])
		}
	}
}

func TestFetchDataDoesNotCollectIPAllowListWhenDisabled(t *testing.T) {
	graphqlRequests := 0
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/orgs/acme":
			_, _ = w.Write([]byte(`{"login":"acme","name":"Acme","url":"https://api.github.com/orgs/acme"}`))
		case "/orgs/acme/teams", "/orgs/acme/members":
			_, _ = w.Write([]byte(`[]`))
		case "/orgs/acme/sso":
			http.NotFound(w, r)
		case "/graphql":
			graphqlRequests++
			t.Fatalf("GraphQL IP allow-list request should not be made when collection is disabled")
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	data, steps, err := fetcher.FetchData(context.Background(), "acme", false)
	if err != nil {
		t.Fatalf("FetchData returned error: %v", err)
	}
	if data.IPAllowList == nil {
		t.Fatal("IPAllowList pointer should be set")
	}
	if *data.IPAllowList != nil {
		t.Fatalf("IPAllowList = %#v, want nil slice when collection is disabled", *data.IPAllowList)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshaling GithubData: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("unmarshaling GithubData: %v", err)
	}
	if value, ok := payload["ip_allow_list"]; !ok || value != nil {
		t.Fatalf("JSON ip_allow_list = %#v, present = %v, want present null", value, ok)
	}
	evaluation, err := rego.New(
		rego.Query("input.ip_allow_list"),
		rego.Input(data),
	).Eval(context.Background())
	if err != nil {
		t.Fatalf("evaluating OPA input: %v", err)
	}
	if len(evaluation) != 1 || len(evaluation[0].Expressions) != 1 {
		t.Fatalf("OPA evaluation = %#v, want one null expression", evaluation)
	}
	if evaluation[0].Expressions[0].Value != nil {
		t.Fatalf("OPA input.ip_allow_list = %#v, want null", evaluation[0].Expressions[0].Value)
	}
	if graphqlRequests != 0 {
		t.Fatalf("GraphQL requests = %d, want 0", graphqlRequests)
	}
	for _, step := range steps {
		if step.Title == "Get IP Allow-List" {
			t.Fatal("IP allow-list collection step should not be present when collection is disabled")
		}
	}
}

func TestFetchSSOUsesRelativeURL(t *testing.T) {
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/orgs/acme/sso" {
			t.Fatalf("path = %s, want /orgs/acme/sso", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"saml_identity_provider":{"sso_url":"https://idp.example/sso","issuer":"https://idp.example"}}`))
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	sso, err := fetcher.fetchSSO(context.Background(), "acme")
	if err != nil {
		t.Fatalf("fetchSSO returned error: %v", err)
	}
	if !sso.Enabled {
		t.Fatal("SSO should be enabled")
	}
	if sso.SSOURL != "https://idp.example/sso" {
		t.Fatalf("SSOURL = %q, want https://idp.example/sso", sso.SSOURL)
	}
	if sso.IDPIssuer != "https://idp.example" {
		t.Fatalf("IDPIssuer = %q, want https://idp.example", sso.IDPIssuer)
	}
}

func TestFetchSSONotFoundMeansDisabled(t *testing.T) {
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	sso, err := fetcher.fetchSSO(context.Background(), "acme")
	if err != nil {
		t.Fatalf("fetchSSO returned error: %v", err)
	}
	if sso.Enabled {
		t.Fatal("SSO should be disabled when the endpoint returns 404")
	}
}

func TestFetchIPAllowListUsesVariablesAndPaginates(t *testing.T) {
	page := 0
	var afterValues []interface{}
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/graphql" {
			t.Fatalf("path = %s, want /graphql", r.URL.Path)
		}

		var request struct {
			Query     string                 `json:"query"`
			Variables map[string]interface{} `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decoding GraphQL request: %v", err)
		}
		if request.Variables["login"] != "acme" {
			t.Fatalf("login variable = %v, want acme", request.Variables["login"])
		}
		afterValues = append(afterValues, request.Variables["after"])

		w.Header().Set("Content-Type", "application/json")
		switch page {
		case 0:
			_, _ = w.Write([]byte(`{"data":{"organization":{"ipAllowListEntries":{"edges":[{"node":{"allowListValue":"192.0.2.0/24","isActive":true,"name":"office"}}],"pageInfo":{"hasNextPage":true,"endCursor":"cursor-1"}}}}}`))
		case 1:
			_, _ = w.Write([]byte(`{"data":{"organization":{"ipAllowListEntries":{"edges":[{"node":{"allowListValue":"198.51.100.0/24","isActive":false,"name":"vpn"}}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}`))
		default:
			t.Fatalf("unexpected GraphQL page request %d", page)
		}
		page++
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	entries, err := fetcher.fetchIPAllowList(context.Background(), "acme")
	if err != nil {
		t.Fatalf("fetchIPAllowList returned error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].AllowListValue != "192.0.2.0/24" || entries[1].AllowListValue != "198.51.100.0/24" {
		t.Fatalf("entries = %#v", entries)
	}
	if len(afterValues) != 2 {
		t.Fatalf("after values = %#v, want two requests", afterValues)
	}
	if afterValues[0] != nil {
		t.Fatalf("first after = %#v, want nil", afterValues[0])
	}
	if afterValues[1] != "cursor-1" {
		t.Fatalf("second after = %#v, want cursor-1", afterValues[1])
	}
}

func TestFetchIPAllowListErrorsWithoutEndCursor(t *testing.T) {
	client, cleanup := testGithubClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"organization":{"ipAllowListEntries":{"edges":[],"pageInfo":{"hasNextPage":true,"endCursor":null}}}}}`))
	}))
	defer cleanup()

	fetcher := NewDataFetcher(hclog.NewNullLogger(), client)
	_, err := fetcher.fetchIPAllowList(context.Background(), "acme")
	if err == nil {
		t.Fatal("fetchIPAllowList should error when a next page has no end cursor")
	}
}
