//go:build integration

package internal

import (
	"context"
	"encoding/json"
	"github.com/google/go-github/v93/github"
	"github.com/hashicorp/go-hclog"
	"os"
	"testing"
)

func TestDataFetcher_FetchData(t *testing.T) {
	t.Run("Fetch organization data and encode", func(t *testing.T) {
		// Simple test to locally validate that data can be fetched correctly
		ctx := context.Background()

		client, err := github.NewClient(github.WithAuthToken(os.Getenv("GITHUB_TOKEN")))
		if err != nil {
			t.Fatal(err)
		}
		fetcher := DataFetcher{
			logger: hclog.NewNullLogger(),
			client: client,
		}

		org, _, err := fetcher.FetchData(ctx, "compliance-framework", false)
		if err != nil {
			t.Error(err)
		}
		t.Log(org)

		// Here I make sure that org can be encoded properly
		data, err := json.Marshal(org)
		if err != nil {
			t.Error(err)
		}
		t.Log(string(data))
	})
}
