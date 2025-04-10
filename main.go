package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-github-settings/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type ConfigValidatorFn func(value string) error

var GithubConfigValidators = map[string]ConfigValidatorFn{
	"api_url": func(value string) error {
		if len(value) == 0 {
			return fmt.Errorf("api_url cannot be empty")
		}
		_, err := url.ParseRequestURI(value)
		if err != nil {
			return err
		}
		return nil
	},
	"api_key": func(value string) error {
		if len(value) == 0 {
			return fmt.Errorf("api_key cannot be empty")
		}
		return nil
	},
	"organization": func(value string) error {
		if len(value) == 0 {
			return fmt.Errorf("organization cannot be empty")
		}
		regex := regexp.MustCompile("^[A-Za-z0-9._-]+$")
		if !regex.MatchString(value) {
			return fmt.Errorf("organization formatted incorrectly, please check")
		}
		return nil
	},
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

	passed_config := req.GetConfig()

	l.logger.Info("Validating configuration")
	errored := false
	for config_key, validator := range GithubConfigValidators {
		value, ok := passed_config[config_key]
		if !ok {
			l.logger.Error("Config Validator failed", "key", config_key, "value", value, "not_set", true)
			errored = true
			continue
		}
		if err := validator(value); err != nil {
			l.logger.Error("Config Validator failed", "key", config_key, "value", value, "error", err)
			errored = true
		}
	}
	if errored {
		l.logger.Error("Invalid configuration for the plugin. Check logs for the issues found")
	} else {
		l.logger.Info("Config Validator passed - continuing")
	}
	l.config = passed_config
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

	dataFetcher := internal.NewDataFetcher(l.logger, l.config)

	data, collectSteps, err := dataFetcher.FetchData()
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

	observations := policyEvaluator.GetObservations()
	findings := policyEvaluator.GetFindings()

	if err = apiHelper.CreateObservations(ctx, observations); err != nil {
		l.logger.Error("Failed to send observations", "error", err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, err
	}

	if err = apiHelper.CreateFindings(ctx, findings); err != nil {
		l.logger.Error("Failed to send findings", "error", err)
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
