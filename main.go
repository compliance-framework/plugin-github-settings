package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-github-settings/internal"
	"github.com/google/go-github/v71/github"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
)

type PluginConfig struct {
	Token        string `mapstructure:"token"`
	Organization string `mapstructure:"organization"`
}

type Validator interface {
	Validate() error
}

func (c *PluginConfig) Validate() error {
	if c.Token == "" {
		return errors.New("token is required")
	}
	if c.Organization == "" {
		return errors.New("organization is required")
	}
	return nil
}

type CompliancePlugin struct {
	logger       hclog.Logger
	config       *PluginConfig
	githubClient *github.Client
}

// Configure, and Eval are called at different times during the plugin execution lifecycle,
// and are responsible for different tasks:
//
// Configure is called on plugin startup. It is primarily used to configure a plugin for its lifetime.
// Here you should store any configurations like usernames and password required by the plugin.
//
// Eval is called once for each scheduled execution with a list of policy paths and it is responsible
// for evaluating each of these policy paths against the data it requires to evaluate those policies.
// The plugin is responsible for collecting the data it needs to evaluate the policies in the Eval
// method and then running the policies against that data.
//
// The simplest way to handle multiple policies is to do an initial lookup of all the data that may
// be required for all policies in the method, and then run the policies against that data. This,
// however, may not be the most efficient way to run policies, and you may want to optimize this
// while writing plugins to reduce the amount of data you need to collect and store in memory. It
// is the plugins responsibility to ensure that it is (reasonably) efficient in its use of
// resources.
//
// A user starts the agent, and passes the plugin and any policy bundles.
//
// The agent will:
//   - Start the plugin
//   - Call Configure() with teh required config
//   - Call Eval() with the first policy bundles (one by one, in turn),
//     so the plugin can report any violations against the configuration
func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {

	// Configure is used to set up any configuration needed by this plugin over its lifetime.
	// This will likely only be called once on plugin startup, which may then run for an extended period of time.

	// In this method, you should save any configuration values to your plugin struct, so you can later
	// re-use them in PrepareForEval and Eval.
	config := &PluginConfig{}
	err := mapstructure.Decode(req.GetConfig(), config)
	if err != nil {
		l.logger.Error("Configuration cannot be decoded. Ensure the correct data has been passed.")
		return nil, err
	}

	// We could potentially move this interface to the shared agent SDK, so it can easily be used across plugins.
	if v, ok := interface{}(config).(Validator); ok {
		err = v.Validate()
		if err != nil {
			l.logger.Error("Configuration validation failed. Ensure the correct data has been passed.")
			return nil, err
		}
	}

	l.config = config
	l.githubClient = github.NewClient(nil).WithAuthToken(l.config.Token)
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	// Eval is used to run policies against the data you've collected in PrepareForEval.
	// Eval will be called N times for every scheduled plugin execution where N is the amount of matching policies
	// passed to the agent.

	// When a user passes multiple policy bundles to the agent, each will be passed to Eval in turn to run against the
	// same data collected in PrepareForEval.

	ctx := context.TODO()

	activities := make([]*proto.Activity, 0)

	dataFetcher := internal.NewDataFetcher(l.logger, l.githubClient)

	data, collectSteps, err := dataFetcher.FetchData(ctx, l.config.Organization)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to fetch data: %w", err)
	}

	stepActivities := append(activities, &proto.Activity{
		Title:       "Collect data",
		Description: "Collect data, and prepare collected data for validation in policy engine",
		Steps:       collectSteps,
	})

	policyEvaluator := internal.NewPolicyEvaluator(ctx, l.logger, stepActivities)

	evalStatus, err := policyEvaluator.Eval(data, request.PolicyPaths)

	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	evidences := policyEvaluator.GetEvidences()

	if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Failed to send evidences", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	resp := &proto.EvalResponse{
		Status: evalStatus,
	}

	return resp, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
