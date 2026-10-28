# Compliance Framework Plugin For Github

This is the individual plugin for polling github settings for organizations and repositories to test for configuration flags that are going to fail compliance checks.

It authenticates to a GitHub organization with a personal access token or as a GitHub App installation (see [GitHub App authentication](#github-app-authentication)). In the future it should query security plans & repositories for specific settings

## Prerequisites

- GoReleaser https://goreleaser.com/install/
- A Github Fine Grain Personal Access Token, or a GitHub App with the equivalent read-only organization permissions (Administration, Members), with the following scopes:
  - `read:org` for the organization to be queried. Note - you _might_ need to be an administrator of the GH Org to work correctly
  - `read:members` to be able to read teams

### IP allow-list data

GitHub organization IP allow-list collection is disabled by default. Enable it only when the plugin is configured with a Classic Personal Access Token with organization administrator permissions. Classic PATs are broad credentials, so prefer leaving `collect_ip_allow_list` set to `false` unless IP allow-list policies are required.

Fine-grained Personal Access Tokens and GitHub App installation tokens may be able to read other organization settings, but GitHub does not currently allow them to query `organization.ipAllowListEntries` through GraphQL.

If IP allow-list data cannot be fetched, the plugin continues with partial data and policies that depend on `ip_allow_list` should report a skip reason instead of evaluating incomplete evidence.

## Building

Once you are ready to serve the plugin, you need to build the binaries which can be used by the agent.

```shell
goreleaser release --snapshot --clean
```

## Usage

You can use this plugin by passing it to the compliance agent

```shell
agent --plugin=[PATH_TO_YOUR_BINARY]
```

## Plugin Configuration

The plugin configuration must be created and managed by the agent, but expects the following configuration keys to be set, otherwise it will fail.

Plugins read their configuration from environment variables, when the path matches the yaml structure.

In the example above, setting an empty token, and an environment variable `CCF_PLUGINS_GITHUB_CONFIG_TOKEN` will use the environment variable.

```shell
export CCF_PLUGINS_GITHUB_CONFIG_TOKEN="github_pat_1234..."
export CCF_PLUGINS_GITHUB_CONFIG_COLLECT_IP_ALLOW_LIST="false"
```

```yaml
---
plugins:
  github:
    config:
      token: "" # Will be read from the CCF_PLUGINS_GITHUB_CONFIG_TOKEN environment variable
      organization: test-org # The name of the organization
      collect_ip_allow_list: false # Set to true only when using a Classic PAT and IP allow-list evidence is required
```

### GitHub App authentication

Instead of a token, the plugin can authenticate as a GitHub App installed on the organization.
Organizations can govern apps centrally, and the plugin only ever holds short-lived
installation tokens, which it renews as they expire.

1. Create a GitHub App (organization *Settings → Developer settings → GitHub Apps*) with
   read-only *Administration* and *Members* organization permissions, and generate a private
   key for it.
2. Install the app on the organization.
3. Configure the plugin with the app's ID, the installation's ID (the number at the end of the
   installation's settings URL) and the private key:

```yaml
---
plugins:
  github:
    config:
      app_id: "123456"
      installation_id: "78901234"
      # The PEM file the app's "Generate a private key" downloads (preferred), or
      private_key_file: /etc/ccf/github-app.pem
      # the key inline, as PEM or base64-encoded PEM, e.g. from
      # CCF_PLUGINS_GITHUB_CONFIG_PRIVATE_KEY
      # private_key: ""
      organization: test-org
```

A `token`, when set, takes precedence over the app settings. As noted above, GitHub does not
let app installation tokens read IP allow-list entries, so keep `collect_ip_allow_list` off.

## Releasing

This plugin is released using goreleaser to build binaries, and Docker to build OCI artifacts (WIP), which will ensure a binary is built for most OS and Architecture combinations.

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page.

[Not Yet Implemented] To run this plugin with the Compliance Agent, you can specify the release. The agent will take care of pulling the correct binary.

```shell
concom agent --plugin=https://github.com/compliance-framework/plugin-template/releases/tag/0.0.1
```
