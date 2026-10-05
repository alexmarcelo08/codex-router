// Claude (Anthropic) OAuth constants shared by the sign-in flow and the
// session module. The browser flow mirrors the official Claude Code CLI: the
// same public client id, the same hosted callback that renders a code for the
// operator to copy back, and the same token endpoint. Values are functions so
// tests -- and a future client revision -- can override them through the
// environment without a code change.

export function anthropicOAuthClientId() {
  return (
    process.env.ANTHROPIC_OAUTH_CLIENT_ID ||
    "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
  ).trim();
}

export function anthropicOAuthAuthorizationEndpoint() {
  return (
    process.env.ANTHROPIC_OAUTH_AUTHORIZATION_URL ||
    "https://claude.com/cai/oauth/authorize"
  ).replace(/\/+$/, "");
}

export function anthropicOAuthTokenUrl() {
  return (
    process.env.ANTHROPIC_OAUTH_TOKEN_URL ||
    "https://platform.claude.com/v1/oauth/token"
  ).replace(/\/+$/, "");
}

// Claude Code registers a hosted redirect that displays the authorization
// code; there is no loopback listener in this flow, so the operator pastes the
// code back instead.
export function anthropicOAuthRedirectUri() {
  return (
    process.env.ANTHROPIC_OAUTH_REDIRECT_URI ||
    "https://platform.claude.com/oauth/code/callback"
  ).trim();
}

export const ANTHROPIC_OAUTH_SCOPES = Object.freeze([
  "user:inference",
  "user:profile",
  "user:sessions:claude_code",
]);

// Anthropic authorizes an OAuth token only for the client that requested it,
// so requests identify as the Claude Code CLI on the wire. The version is
// deliberately overridable: a future client revision can be adopted without
// touching code.
export function anthropicOAuthUserAgent() {
  return (
    process.env.ANTHROPIC_OAUTH_USER_AGENT ||
    "claude-cli/2.0.0 (external, cli)"
  ).trim();
}

// Required beta gate on every request that authenticates with an OAuth token
// instead of an API key.
export const ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20";
