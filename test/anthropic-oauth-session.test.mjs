import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  anthropicOAuthStatus,
  ensureFreshAnthropicOAuthToken,
  readAnthropicOAuthToken,
  removeAnthropicOAuthToken,
  saveAnthropicOAuthToken,
  validateAnthropicOAuthToken,
} from "../src/anthropic-oauth-session.mjs";

const NOW = 1_700_000_000_000;
const noDelay = async () => {};

async function withToken(token, run) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "anthropic-oauth-"));
  const tokenPath = path.join(directory, "token.json");
  writeFileSync(tokenPath, JSON.stringify(token), { mode: 0o600 });
  const previous = process.env.ANTHROPIC_OAUTH_TOKEN_PATH;
  process.env.ANTHROPIC_OAUTH_TOKEN_PATH = tokenPath;
  try {
    return await run({ tokenPath });
  } finally {
    if (previous === undefined) delete process.env.ANTHROPIC_OAUTH_TOKEN_PATH;
    else process.env.ANTHROPIC_OAUTH_TOKEN_PATH = previous;
    rmSync(directory, { recursive: true, force: true });
  }
}

function freshToken(overrides = {}) {
  return {
    access_token: "access-old",
    refresh_token: "refresh-old",
    expires_at: Math.floor(NOW / 1_000) + 3_600,
    expires_in: 3_600,
    token_type: "Bearer",
    account_email: "user@example.com",
    ...overrides,
  };
}

function jsonResponse(status, payload) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  };
}

test("keeps an active token without refreshing", async () => {
  await withToken(freshToken(), async () => {
    let refreshes = 0;
    const token = await ensureFreshAnthropicOAuthToken({
      now: () => NOW,
      fetchImpl: async () => {
        refreshes += 1;
        throw new Error("should not run");
      },
    });
    assert.equal(token, "access-old");
    assert.equal(refreshes, 0);
  });
});

test("refreshes inside the window and persists rotation", async () => {
  await withToken(
    freshToken({ expires_at: Math.floor(NOW / 1_000) + 120 }),
    async ({ tokenPath }) => {
      const token = await ensureFreshAnthropicOAuthToken({
        now: () => NOW,
        delayImpl: noDelay,
        fetchImpl: async (url, options) => {
          assert.match(String(url), /oauth\/token/);
          const body = JSON.parse(options.body);
          assert.equal(body.grant_type, "refresh_token");
          assert.equal(body.refresh_token, "refresh-old");
          assert.ok(body.client_id);
          return jsonResponse(200, {
            access_token: "access-new",
            refresh_token: "refresh-new",
            expires_in: 3_600,
            token_type: "Bearer",
          });
        },
      });
      assert.equal(token, "access-new");
      const stored = JSON.parse(readFileSync(tokenPath, "utf8"));
      assert.equal(stored.access_token, "access-new");
      assert.equal(stored.refresh_token, "refresh-new");
      assert.equal(stored.account_email, "user@example.com");
    },
  );
});

test("keeps the current token on a transient refresh failure before hard expiry", async () => {
  await withToken(
    freshToken({ expires_at: Math.floor(NOW / 1_000) + 200 }),
    async () => {
      const token = await ensureFreshAnthropicOAuthToken({
        now: () => NOW,
        delayImpl: noDelay,
        fetchImpl: async () => jsonResponse(503, { error: "overloaded" }),
      });
      assert.equal(token, "access-old");
    },
  );
});

test("treats a rejected refresh as a revoked session", async () => {
  await withToken(
    freshToken({ expires_at: Math.floor(NOW / 1_000) + 120 }),
    async ({ tokenPath }) => {
      await assert.rejects(
        ensureFreshAnthropicOAuthToken({
          now: () => NOW,
          delayImpl: noDelay,
          fetchImpl: async () => jsonResponse(400, { error: "invalid_grant" }),
        }),
        (error) => error?.code === "oauth_unauthorized",
      );
      const stored = JSON.parse(readFileSync(tokenPath, "utf8"));
      assert.equal(stored.access_token, "");
      assert.equal(stored.refresh_token, "");
      assert.throws(() => readAnthropicOAuthToken(), /sign in again/);
      assert.equal(anthropicOAuthStatus().configured, false);
    },
  );
});

test("saves and removes a session document", async () => {
  await withToken(freshToken(), async ({ tokenPath }) => {
    saveAnthropicOAuthToken({ ...freshToken(), access_token: "saved" });
    assert.equal(readAnthropicOAuthToken().access_token, "saved");
    assert.equal(removeAnthropicOAuthToken(), true);
    assert.equal(existsSync(tokenPath), false);
    assert.equal(removeAnthropicOAuthToken(), false);
  });
});

test("validate rejects incomplete credential documents", () => {
  assert.throws(() => validateAnthropicOAuthToken({}), /missing/);
  assert.throws(
    () =>
      validateAnthropicOAuthToken({
        access_token: "a",
        refresh_token: "",
        expires_at: 1,
        expires_in: 1,
      }),
    /refresh credential is missing/,
  );
  assert.throws(
    () =>
      validateAnthropicOAuthToken({
        access_token: "",
        refresh_token: "",
        expires_at: 0,
        expires_in: 0,
      }),
    /sign in again/,
  );
});
