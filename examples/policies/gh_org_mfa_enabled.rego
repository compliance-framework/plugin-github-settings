package compliance_framework.mfa_enabled

violation[{
    "title": "Two Factor Authentication is required at an organization level",
    "description": "Two factor authentication should be enabled and enforced for all users within the Github Organization to make it harder for malicious actors to gain access to the organizations settings and repositories & settings",
    "remarks": "More information from Github can be found here: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization"
}] if {
    input.settings.two_factor_requirement_enabled == false
}