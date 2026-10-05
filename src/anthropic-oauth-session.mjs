import {
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import {
  anthropicOAuthClientId,
  anthropicOAuthTokenUrl,
  anthropicOAuthUserAgent,
} from "./anthropic-oauth-constants.mjs";
import { writePrivateJson } from "./file-security.mjs";
import { STATE_DIR } from "./paths.mjs";

// Refresh once the token is within this window of expiry (or past half its
// lifetime, whichever is later). A fixed floor keeps a short-lived token from
// being refreshed on every turn while still covering the gap between "fresh
// enough to read" and "expired by the time the upstream answers".
const REFRESH_WINDOW_SECONDS = 300;
const RETRYABLE_REFRESH_STATUSES = new Set([429, 500, 502, 503, 504]);
const MAX_REFRESH_ATTEMPTS = 3;

let refreshInFlight;

export function anthropicOAuthTokenPath() {
  return (
    process.env.ANTHROPIC_OAUTH_TOKEN_PATH ||
    path.join(STATE_DIR, "anthropic-oauth.json")
  );
}

function lockTarget() {
  return `${anthropicOAuthTokenPath()}.guard`;
}

function oauthError(message, { code = "oauth_error", status = 502, cause } = {}) {
  const error = new Error(message);
  error.code = code;
  error.status = status;
  if (cause !== undefined) error.cause = cause;
  return error;
}

function unauthorizedError(message) {
  return oauthError(message, { code: "oauth_unauthorized", status: 401 });
}

function transientError(message, cause) {
  return oauthError(message, { code: "oauth_transient", status: 503, cause });
}

function defaultDelay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function validateAnthropicOAuthToken(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw unauthorizedError("Claude OAuth credential file is invalid; sign in again.");
  }
  if (
    value.access_token === "" &&
    value.refresh_token === "" &&
    Number(value.expires_at) === 0 &&
    Number(value.expires_in) === 0
  ) {
    throw unauthorizedError("Claude OAuth session was rejected; sign in again.");
  }
  if (typeof value.access_token !== "string" || !value.access_token) {
    throw unauthorizedError("Claude OAuth credential is missing; sign in again.");
  }
  if (typeof value.refresh_token !== "string" || !value.refresh_token) {
    throw unauthorizedError("Claude OAuth refresh credential is missing; sign in again.");
  }
  const expiresAt = Number(value.expires_at);
  const expiresIn = Number(value.expires_in);
  if (!Number.isFinite(expiresAt) || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw unauthorizedError("Claude OAuth credential has invalid expiry metadata; sign in again.");
  }
  return {
    access_token: value.access_token,
    refresh_token: value.refresh_token,
    expires_at: expiresAt,
    expires_in: expiresIn,
    scope: typeof value.scope === "string" ? value.scope : undefined,
    token_type: typeof value.token_type === "string" ? value.token_type : "Bearer",
    account_email:
      typeof value.account_email === "string" && value.account_email
        ? value.account_email
        : undefined,
    subscription_type:
      typeof value.subscription_type === "string" && value.subscription_type
        ? value.subscription_type
        : undefined,
  };
}

export function readAnthropicOAuthToken() {
  const tokenPath = anthropicOAuthTokenPath();
  if (!existsSync(tokenPath)) {
    throw unauthorizedError("Claude OAuth credentials were not found; sign in first.");
  }
  try {
    return validateAnthropicOAuthToken(JSON.parse(readFileSync(tokenPath, "utf8")));
  } catch (error) {
    if (error?.code === "oauth_unauthorized") throw error;
    throw unauthorizedError("Claude OAuth credential file is invalid; sign in again.");
  }
}

export function anthropicOAuthCredential() {
  try {
    const token = readAnthropicOAuthToken();
    return {
      value: token.access_token,
      source: `Claude OAuth session (${anthropicOAuthTokenPath()})`,
      persistent: true,
    };
  } catch {
    return undefined;
  }
}

export function anthropicOAuthStatus() {
  const tokenPath = anthropicOAuthTokenPath();
  const credential = anthropicOAuthCredential();
  return credential
    ? { configured: true, source: credential.source, credentialPresent: true }
    : { configured: false, credentialPresent: existsSync(tokenPath), tokenPath };
}

// The tombstone a rejected refresh writes is deliberately invalid as a
// credential (empty strings, zero expiry) so every later read reports the
// session as revoked; only the validated save path enforces the shape.
function writeTokenDocument(token) {
  writePrivateJson(
    anthropicOAuthTokenPath(),
    { version: 1, ...token },
    { directoryMode: 0o700 },
  );
}

function atomicSaveToken(token) {
  const normalized = validateAnthropicOAuthToken(token);
  writeTokenDocument(normalized);
  return normalized;
}

export function saveAnthropicOAuthToken(token) {
  return atomicSaveToken(token);
}

export function removeAnthropicOAuthToken() {
  const target = anthropicOAuthTokenPath();
  if (!existsSync(target)) return false;
  unlinkSync(target);
  return true;
}

function shouldRefresh(token, nowMs) {
  const threshold = Math.max(REFRESH_WINDOW_SECONDS, token.expires_in * 0.5);
  return Math.floor(nowMs / 1_000) >= token.expires_at - threshold;
}

function isHardExpired(token, nowMs) {
  return Math.floor(nowMs / 1_000) >= token.expires_at;
}

function sameToken(left, right) {
  return (
    left.access_token === right.access_token &&
    left.refresh_token === right.refresh_token &&
    left.expires_at === right.expires_at
  );
}

function revokedTombstone(token) {
  return {
    access_token: "",
    refresh_token: "",
    expires_at: 0,
    expires_in: 0,
    scope: token.scope,
    token_type: token.token_type,
  };
}

async function requestRefresh(
  refreshTokenValue,
  { fetchImpl = fetch, now = Date.now, delayImpl = defaultDelay } = {},
) {
  let lastError;
  for (let attempt = 0; attempt < MAX_REFRESH_ATTEMPTS; attempt += 1) {
    let response;
    try {
      response = await fetchImpl(anthropicOAuthTokenUrl(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "anthropic-version": "2023-06-01",
          "User-Agent": anthropicOAuthUserAgent(),
        },
        body: JSON.stringify({
          grant_type: "refresh_token",
          client_id: anthropicOAuthClientId(),
          refresh_token: refreshTokenValue,
        }),
        signal: AbortSignal.timeout(30_000),
      });
    } catch (error) {
      lastError = transientError(
        "Claude OAuth refresh could not reach the authentication service.",
        error,
      );
      if (attempt < MAX_REFRESH_ATTEMPTS - 1) await delayImpl(2 ** attempt * 1_000);
      continue;
    }

    const payload = await response.json().catch(() => ({}));
    if (response.ok) {
      const expiresIn = Number(payload.expires_in);
      if (
        typeof payload.access_token !== "string" ||
        !payload.access_token ||
        !Number.isFinite(expiresIn) ||
        expiresIn <= 0
      ) {
        throw oauthError("Claude OAuth refresh returned an incomplete response.");
      }
      return {
        access_token: payload.access_token,
        // Rotation is optional: a response without a new refresh token keeps
        // the current one instead of bricking the session.
        refresh_token:
          typeof payload.refresh_token === "string" && payload.refresh_token
            ? payload.refresh_token
            : refreshTokenValue,
        expires_at: Math.floor(now() / 1_000) + expiresIn,
        expires_in: expiresIn,
        scope: typeof payload.scope === "string" ? payload.scope : undefined,
        token_type: typeof payload.token_type === "string" ? payload.token_type : "Bearer",
        account_email:
          typeof payload.account?.email_address === "string"
            ? payload.account.email_address
            : undefined,
      };
    }
    const code = typeof payload.error === "string" ? payload.error : "oauth_error";
    if (response.status === 401 || response.status === 403 || code === "invalid_grant") {
      throw unauthorizedError("Claude OAuth refresh was rejected; sign in again.");
    }
    if (!RETRYABLE_REFRESH_STATUSES.has(response.status)) {
      throw oauthError(`Claude OAuth refresh failed with HTTP ${response.status}.`);
    }
    lastError = transientError(`Temporary Claude OAuth error: HTTP ${response.status}.`);
    if (attempt < MAX_REFRESH_ATTEMPTS - 1) await delayImpl(2 ** attempt * 1_000);
  }
  throw lastError || transientError("Claude OAuth refresh failed.");
}

export async function ensureFreshAnthropicOAuthToken({
  force = false,
  fetchImpl = fetch,
  now = Date.now,
  delayImpl = defaultDelay,
} = {}) {
  const current = refreshInFlight;
  if (current) {
    if (!force || current.force) return current.promise;
    try {
      await current.promise;
    } catch {
      // The original caller owns its failure. A forced caller still needs its
      // own attempt because the non-forced refresh may have kept the old
      // token.
    }
    return ensureFreshAnthropicOAuthToken({ force: true, fetchImpl, now, delayImpl });
  }

  const promise = (async () => {
    const initial = readAnthropicOAuthToken();
    if (!force && !shouldRefresh(initial, now())) return initial.access_token;

    let release;
    try {
      // Lazy: the status path imports this module before setup has installed
      // Node dependencies, and only a credential mutation needs the lock.
      const { default: lockfile } = await import("proper-lockfile");
      mkdirSync(path.dirname(lockTarget()), { recursive: true, mode: 0o700 });
      writeFileSync(lockTarget(), "", { flag: "a", mode: 0o600 });
      release = await lockfile.lock(lockTarget(), {
        retries: { retries: 120, factor: 1, minTimeout: 500, maxTimeout: 1_000 },
        stale: 5_000,
        realpath: false,
      });
    } catch (error) {
      if (!force && !isHardExpired(initial, now())) return initial.access_token;
      throw transientError("Claude OAuth refresh lock is unavailable.", error);
    }

    try {
      const latest = readAnthropicOAuthToken();
      if (!force && !shouldRefresh(latest, now())) return latest.access_token;
      if (force && !sameToken(initial, latest)) return latest.access_token;
      try {
        const refreshed = await requestRefresh(latest.refresh_token, {
          fetchImpl,
          now,
          delayImpl,
        });
        if (!refreshed.account_email && latest.account_email) {
          refreshed.account_email = latest.account_email;
        }
        if (!refreshed.subscription_type && latest.subscription_type) {
          refreshed.subscription_type = latest.subscription_type;
        }
        atomicSaveToken(refreshed);
        return refreshed.access_token;
      } catch (error) {
        if (error?.code === "oauth_unauthorized") {
          await delayImpl(100);
          const recovered = readAnthropicOAuthToken();
          if (recovered.refresh_token !== latest.refresh_token) {
            return recovered.access_token;
          }
          writeTokenDocument(revokedTombstone(latest));
        } else if (error?.code === "oauth_transient" && !force && !isHardExpired(latest, now())) {
          return latest.access_token;
        }
        throw error;
      }
    } finally {
      try {
        await release();
      } catch {
        // The lock may have been reaped as stale after a long network pause.
      }
    }
  })().finally(() => {
    if (refreshInFlight?.promise === promise) refreshInFlight = undefined;
  });
  refreshInFlight = { promise, force };
  return promise;
}
