import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import readline from "node:readline";

import {
  ANTHROPIC_OAUTH_SCOPES,
  anthropicOAuthAuthorizationEndpoint,
  anthropicOAuthClientId,
  anthropicOAuthRedirectUri,
  anthropicOAuthTokenUrl,
  anthropicOAuthUserAgent,
} from "./anthropic-oauth-constants.mjs";
import { saveAnthropicOAuthToken } from "./anthropic-oauth-session.mjs";
import { installStableFetchTransport } from "./fetch-transport.mjs";

installStableFetchTransport();

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function verifierChallenge(verifier) {
  return base64Url(createHash("sha256").update(verifier).digest());
}

export function generateAnthropicOAuthPkce(random = randomBytes) {
  const verifier = base64Url(random(64));
  return { verifier, challenge: verifierChallenge(verifier) };
}

export function anthropicOAuthAuthorizationUrl(
  verifier,
  state,
  { redirectUri = anthropicOAuthRedirectUri() } = {},
) {
  const url = new URL(anthropicOAuthAuthorizationEndpoint());
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", anthropicOAuthClientId());
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", ANTHROPIC_OAUTH_SCOPES.join(" "));
  url.searchParams.set("code_challenge", verifierChallenge(verifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  return url.toString();
}

// The hosted callback renders "<code>#<state>"; a pasted bare code is accepted
// too, because the operator may copy only the first half.
export function parseAnthropicOAuthInput(raw) {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) throw new Error("No authorization code was pasted.");
  const hash = trimmed.indexOf("#");
  const code = (hash === -1 ? trimmed : trimmed.slice(0, hash)).trim();
  const state = hash === -1 ? undefined : trimmed.slice(hash + 1).trim() || undefined;
  if (!code || /\s/.test(code)) {
    throw new Error("The pasted authorization code is not valid.");
  }
  return { code, state };
}

export async function exchangeAnthropicOAuthCode(
  code,
  verifier,
  { state, fetchImpl = fetch, now = Date.now, redirectUri = anthropicOAuthRedirectUri() } = {},
) {
  const response = await fetchImpl(anthropicOAuthTokenUrl(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": anthropicOAuthUserAgent(),
    },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code,
      client_id: anthropicOAuthClientId(),
      redirect_uri: redirectUri,
      code_verifier: verifier,
      ...(state ? { state } : {}),
    }),
    signal: AbortSignal.timeout(30_000),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const description =
      typeof payload.error_description === "string"
        ? payload.error_description.slice(0, 200)
        : "";
    const error = new Error(
      `Claude sign-in token exchange failed with HTTP ${response.status}${description ? `: ${description}` : "."}`,
    );
    error.code = response.status >= 500 ? "oauth_transient" : "oauth_unauthorized";
    error.status = response.status >= 500 ? 503 : 401;
    throw error;
  }
  const expiresIn = Number(payload.expires_in);
  if (
    typeof payload.access_token !== "string" ||
    !payload.access_token ||
    typeof payload.refresh_token !== "string" ||
    !payload.refresh_token ||
    !Number.isFinite(expiresIn) ||
    expiresIn <= 0
  ) {
    throw new Error("Claude sign-in token exchange returned an incomplete response.");
  }
  return {
    access_token: payload.access_token,
    refresh_token: payload.refresh_token,
    expires_at: Math.floor(now() / 1_000) + expiresIn,
    expires_in: expiresIn,
    scope: typeof payload.scope === "string" ? payload.scope : undefined,
    token_type: typeof payload.token_type === "string" ? payload.token_type : "Bearer",
    account_email:
      typeof payload.account?.email_address === "string"
        ? payload.account.email_address
        : undefined,
    subscription_type:
      typeof payload.subscription_type === "string" ? payload.subscription_type : undefined,
  };
}

function openBrowser(url) {
  let command;
  let args;
  let env;
  if (process.platform === "darwin") {
    command = "open";
    args = [url];
  } else if (process.platform === "win32") {
    command = "powershell.exe";
    args = [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "Start-Process $env:CODEX_ROUTER_BROWSER_URL",
    ];
    env = { ...process.env, CODEX_ROUTER_BROWSER_URL: url };
  } else {
    command = "xdg-open";
    args = [url];
  }
  const child = spawn(command, args, {
    stdio: "ignore",
    detached: true,
    windowsHide: true,
    ...(env ? { env } : {}),
  });
  child.on("error", () => {});
  child.unref();
}

export function promptForAnthropicOAuthCode({
  input = process.stdin,
  output = process.stdout,
  timeoutMs = 10 * 60_000,
} = {}) {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({ input, output });
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(
      () => finish(new Error("Claude sign-in timed out; run it again.")),
      timeoutMs,
    );
    rl.question("Paste the authorization code from the browser, then press Enter: ", (answer) =>
      finish(null, answer),
    );
    rl.once("close", () =>
      finish(new Error("Claude sign-in was cancelled before an authorization code was entered.")),
    );
  });
}

export async function signInAnthropic({
  fetchImpl = fetch,
  now = Date.now,
  input = process.stdin,
  output = process.stdout,
  open = openBrowser,
  timeoutMs = 10 * 60_000,
} = {}) {
  // The browser hands the operator a code to paste; there is no callback
  // listener a piped stdio pair could complete.
  if (input === process.stdin && !input.isTTY) {
    throw new Error(
      "The Claude sign-in is interactive. Run `./bin/providers login anthropic-oauth` in a terminal.",
    );
  }
  const pkce = generateAnthropicOAuthPkce();
  const state = randomUUID();
  const url = anthropicOAuthAuthorizationUrl(pkce.verifier, state);
  output.write(
    "Sign in to Claude with a Pro or Max account.\n" +
      "After approving access, the browser shows an authorization code. Copy it, then paste it here.\n\n" +
      `  ${url}\n\n`,
  );
  try {
    open(url);
  } catch {
    // The URL is already printed; a browser-open failure is not fatal.
  }
  const raw = await promptForAnthropicOAuthCode({ input, output, timeoutMs });
  const { code, state: returnedState } = parseAnthropicOAuthInput(raw);
  if (returnedState && returnedState !== state) {
    throw new Error("The pasted code belongs to a different sign-in attempt; run the sign-in again.");
  }
  const token = await exchangeAnthropicOAuthCode(code, pkce.verifier, {
    fetchImpl,
    now,
    state: returnedState || state,
  });
  const stored = saveAnthropicOAuthToken(token);
  output.write(
    stored.account_email ? `Signed in as ${stored.account_email}.\n` : "Signed in.\n",
  );
  return stored;
}
