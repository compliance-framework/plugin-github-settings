# Changelog

## [0.8.0](https://github.com/compliance-framework/plugin-github-settings/compare/v0.7.0...v0.8.0) (2026-10-29)


### Features

* GitHub App authentication ([#33](https://github.com/compliance-framework/plugin-github-settings/issues/33)) ([67a1f3e](https://github.com/compliance-framework/plugin-github-settings/commit/67a1f3e9e53c5a31640c32a947d75fba6c5783b0))


### Bug Fixes

* **deps:** build with the go1.26.10 toolchain so Renovate can ship Go security fixes ([#35](https://github.com/compliance-framework/plugin-github-settings/issues/35)) ([9ec6142](https://github.com/compliance-framework/plugin-github-settings/commit/9ec614269ac4364f9f174591307cacec9336f20a))

## [0.7.0](https://github.com/compliance-framework/plugin-github-settings/compare/v0.6.0...v0.7.0) (2026-10-28)


### ⚠ BREAKING CHANGES

* **deps:** `UsersService.Unsuspend` now takes an `UnsuspendUserRequest` body argument.
    - refactor!: Pass repository creation by value
    ([#&#8203;4616](https://redirect.github.com/google/go-github/issues/4616))
    `RepositoriesService.Create` now requires a
    `CreateRepositoryRequest` value instead of a `*Repository`.
    - refactor!: Rename `LockIssueOptions`,
    `PullRequestBranchUpdateOptions`, and `UserSuspendOptions` to
    `...Request` and pass them by value
    ([#&#8203;4612](https://redirect.github.com/google/go-github/issues/4612))
    `LockIssueOptions`, `PullRequestBranchUpdateOptions`,
    and `UserSuspendOptions` are renamed to `LockIssueRequest`,
    `UpdatePullRequestBranchRequest`, and `SuspendUserRequest` and are
    passed by value to `IssuesService.Lock`,
    `PullRequestsService.UpdateBranch`, and `UsersService.Suspend`;
    `LockIssueRequest.LockReason` is now `*string`.
    - refactor!: Pass the Projects v2 item body types by value and rename
    them to `...Request`
    ([#&#8203;4609](https://redirect.github.com/google/go-github/issues/4609))
    `AddProjectItemOptions` and `UpdateProjectItemOptions`
    are renamed to `AddProjectItemRequest` and `UpdateProjectItemRequest`
    and passed by value; `AddProjectItemRequest.Type` is no longer a
    pointer; `UpdateProjectItemOptions.Archived` is removed.
    - refactor!: Rename `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` to `...Request` and pass them by
    value
    ([#&#8203;4607](https://redirect.github.com/google/go-github/issues/4607))
    `RepositoryCreateForkOptions` and
    `RepositoryAddCollaboratorOptions` are renamed to `CreateForkRequest`
    and `AddCollaboratorRequest`; `RepositoriesService.CreateFork` and
    `RepositoriesService.AddCollaborator` now take them by value instead of
    by pointer; `CreateForkRequest.Organization`, `CreateForkRequest.Name`,
    `CreateForkRequest.DefaultBranchOnly` and
    `AddCollaboratorRequest.Permission` are now pointers.
    - refactor!: Pass the Teams body types by value and rename them to
    `...Request`
    ([#&#8203;4606](https://redirect.github.com/google/go-github/issues/4606))
    `TeamAddTeamMembershipOptions`,
    `TeamAddTeamRepoOptions` and `TeamProjectOptions` are renamed to
    `AddTeamMembershipRequest`, `AddTeamRepoRequest` and
    `AddTeamProjectRequest`; `TeamsService.AddTeamMembershipByID`,
    `AddTeamMembershipBySlug`, `AddTeamRepoByID`, `AddTeamRepoBySlug`,
    `AddTeamProjectByID` and `AddTeamProjectBySlug` now take them by value
    instead of by pointer; `AddTeamMembershipRequest.Role` and
    `AddTeamRepoRequest.Permission` are now `*string`.
    - refactor!: Pass the secret scanning body types by value and rename
    them to `...Request`
    ([#&#8203;4548](https://redirect.github.com/google/go-github/issues/4548))
    `SecretScanningAlertUpdateOptions` and
    `SecretScanningPatternConfigsUpdateOptions` are renamed to
    `UpdateSecretScanningAlertRequest` and
    `UpdateSecretScanningPatternConfigsRequest`;
    `SecretScanningService.UpdateAlert`, `UpdatePatternConfigsForEnterprise`
    and `UpdatePatternConfigsForOrg` now take them by value;
    `UpdateSecretScanningAlertRequest.State` is now `*string`.
    - fix!: Match request body fields to the OpenAPI schemas
    ([#&#8203;4581](https://redirect.github.com/google/go-github/issues/4581))
    Many required request body fields are now passed by
    value.
    - fix!: Send credentials only to configured origins
    ([#&#8203;4564](https://redirect.github.com/google/go-github/issues/4564))
    Credentials are sent only to a client's configured API
    and upload origins — every other destination, including a redirect hop,
    goes out unauthenticated. A request body aimed outside those origins is
    refused. `BasicAuthTransport` and `UnauthenticatedRateLimitedTransport`
    gained `AllowedOrigins`, which GitHub Enterprise users must set.
    - refactor!: Pass org invitation requests by value
    ([#&#8203;4551](https://redirect.github.com/google/go-github/issues/4551))
    `OrganizationsService.CreateOrgInvitation` now takes
    `CreateOrgInvitationRequest` (by value);
    `CreateOrgInvitationRequest.TeamID` is now `TeamIDs`.

### Bug Fixes

* **deps:** bump agent to v0.9.3, workflows to v1.7.0 ([#28](https://github.com/compliance-framework/plugin-github-settings/issues/28)) ([ffc5683](https://github.com/compliance-framework/plugin-github-settings/commit/ffc5683c3f361644ac19c36e0bc84e4136f88aaf))
* **deps:** bump agent to v0.9.4 ([#32](https://github.com/compliance-framework/plugin-github-settings/issues/32)) ([3550b30](https://github.com/compliance-framework/plugin-github-settings/commit/3550b3068c9acde2c01f8fca116f34eab94e25f5))
* **deps:** update module github.com/google/go-github/v71 to v93 ([#31](https://github.com/compliance-framework/plugin-github-settings/issues/31)) ([f1fb43e](https://github.com/compliance-framework/plugin-github-settings/commit/f1fb43e098f773c2a5919e98f00ff164718efdd5))
* **deps:** update module github.com/hashicorp/go-plugin to v1.8.0 ([#30](https://github.com/compliance-framework/plugin-github-settings/issues/30)) ([d6e9177](https://github.com/compliance-framework/plugin-github-settings/commit/d6e9177f36e53d66177e03f005dc928f2a4ca69d))

## [0.6.0](https://github.com/compliance-framework/plugin-github-settings/compare/v0.5.0...v0.6.0) (2026-10-14)


### Features

* pass policy data to policy evaluation and depend on agent v0.8.0-rc4 ([f1e87c5](https://github.com/compliance-framework/plugin-github-settings/commit/f1e87c562943cfe67ebb62aa972655ad315dfbc5))


### Bug Fixes

* **deps:** bump agent to v0.9.2 ([#27](https://github.com/compliance-framework/plugin-github-settings/issues/27)) ([38440ba](https://github.com/compliance-framework/plugin-github-settings/commit/38440baf0db779216d28a9ccb4db0d3bd1e99f5b))
* **deps:** bump compliance-framework/agent to v0.9.1 ([#16](https://github.com/compliance-framework/plugin-github-settings/issues/16)) ([8c3e37d](https://github.com/compliance-framework/plugin-github-settings/commit/8c3e37d2184edc1a441e834f6a5e11658271bd61))
* **deps:** update security fixes (gomod) [security] ([#26](https://github.com/compliance-framework/plugin-github-settings/issues/26)) ([9e0b390](https://github.com/compliance-framework/plugin-github-settings/commit/9e0b3907cd2419408384ee507c064ca42eaa4cba))
