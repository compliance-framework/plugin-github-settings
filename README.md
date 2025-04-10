# Compliance Framework Plugin For Github

This is the individual plugin for polling github settings for organizations and repositories to test for configuration flags that are going to fail compliance checks. 

For the moment, it is solely limited to authenticated Github organizations with a Github PAT, but in the future it should query security plans & repositories for specific settings 

## Prerequisites

* GoReleaser https://goreleaser.com/install/
* Github Fine Grain Personal Access Token with the following scopes:
    * `read:org` for the organization to be queried. Note - you *might* need to be an administrator of the GH Org to work correctly


## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Usage

You can use this plugin by passing it to the compliiance agent

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

## Plugin Configuration

The plugin configuration must be created and managed by the agent, but expects the following configuration keys to be set, otherwise it will fail
```yaml
...
plugins:
    github:
        config:
            api_key: github_pat_1234....  # The configured Github PAT for the organization scopes
            api_url: https://api.github.com  # The URL for the API endpoint for GH installations on-premise 
            organization: test-org  # The name of the organization
...
```

## Releasing

This plugin is released using goreleaser to build binaries, and Docker to build OCI artifacts (WIP), which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page.

[Not Yet Implemented] To run this plugin with the Compliance Agent, you can specify the release. The agent will take care of pulling the correct binary.

```shell
concom agent --plugin=https://github.com/compliance-framework/plugin-template/releases/tag/0.0.1
```

## Todo

- [X] Pull Organization settings as an authenticated user 
- [ ] Pull repository information for the listed Organization
- [ ] Populate Security Plans and map them to the repositories to ensure that settings are enabled
- [ ] Sensible defaults for the configuration
- [ ] Better error handling for sending issues back to the agent