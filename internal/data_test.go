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
