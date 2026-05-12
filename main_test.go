package main

import (
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func TestConfigureDefaultsCollectIPAllowListToFalse(t *testing.T) {
	plugin := &CompliancePlugin{logger: hclog.NewNullLogger()}

	_, err := plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":        "token",
			"organization": "acme",
		},
	})
	if err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if plugin.config.CollectIPAllowList {
		t.Fatal("CollectIPAllowList should default to false")
	}
}

func TestConfigureParsesCollectIPAllowList(t *testing.T) {
	plugin := &CompliancePlugin{logger: hclog.NewNullLogger()}

	_, err := plugin.Configure(&proto.ConfigureRequest{
		Config: map[string]string{
			"token":                 "token",
			"organization":          "acme",
			"collect_ip_allow_list": "true",
		},
	})
	if err != nil {
		t.Fatalf("Configure returned error: %v", err)
	}
	if !plugin.config.CollectIPAllowList {
		t.Fatal("CollectIPAllowList should be true when configured")
	}
}
