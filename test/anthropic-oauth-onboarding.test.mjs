import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import {
  anthropicOAuthAuthorizationUrl,
  exchangeAnthropicOAuthCode,
  generateAnthropicOAuthPkce,
  parseAnthropicOAuthInput,
  signInAnthropic,
} from "../src/anthropic-oauth-onboarding.mjs";

test("generates an S256 PKCE pair", () => {
  const pkce = generateAnthropicOAuthPkce();
  const expected = Buffer.from(
    createHash("sha256").update(pkce.verifier).digest(),
  ).toString("base64url");
  assert.equal(pkce.challenge, expected);
  assert.match(pkce.verifier, /^[A-Za-z0-9_-]{43,}$/);
});

test("builds the Claude authorization URL", () => {
  const url = new URL(anthropicOAuthAuthorizationUrl("verifier-value", "state-value"));
  assert.equal(url.origin + url.pathname, "https://claude.com/cai/oauth/authorize");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code"), "true");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("state"), "state-value");
  assert.match(url.searchParams.get("scope"), /user:inference/);
  assert.ok(url.searchParams.get("client_id"));
  assert.ok(url.searchParams.get("redirect_uri"));
});

test("parses pasted code and state", () => {
  assert.deepEqual(parseAnthropicOAuthInput("abc#def"), { code: "abc", state: "def" });
  assert.deepEqual(parseAnthropicOAuthInput("  abc  "), { code: "abc", state: undefined });
  assert.deepEqual(parseAnthropicOAuthInput("abc#"), { code: "abc", state: undefined });
  assert.throws(() => parseAnthropicOAuthInput("   "), /No authorization code/);
  assert.throws(() => parseAnthropicOAuthInput("bad code"), /not valid/);
});

test("exchanges the pasted code for tokens", async () => {
  const now = 1_700_000_000_000;
  const token = await exchangeAnthropicOAuthCode("the-code", "the-verifier", {
    state: "the-state",
    now: () => now,
    fetchImpl: async (url, options) => {
      assert.match(String(url), /oauth\/token/);
      const body = JSON.parse(options.body);
      assert.equal(body.grant_type, "authorization_code");
      assert.equal(body.code, "the-code");
      assert.equal(body.code_verifier, "the-verifier");
      assert.equal(body.state, "the-state");
      assert.ok(body.redirect_uri);
      assert.ok(body.client_id);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "access-token",
          refresh_token: "refresh-token",
          expires_in: 60,
          account: { email_address: "person@example.com" },
        }),
      };
    },
  });
  assert.equal(token.access_token, "access-token");
  assert.equal(token.refresh_token, "refresh-token");
  assert.equal(token.expires_at, Math.floor(now / 1_000) + 60);
  assert.equal(token.account_email, "person@example.com");
});

test("maps a rejected exchange to an unauthorized error", async () => {
  await assert.rejects(
    exchangeAnthropicOAuthCode("code", "verifier", {
      fetchImpl: async () => ({
        ok: false,
        status: 401,
        json: async () => ({ error: "invalid_grant", error_description: "bad code" }),
      }),
    }),
    (error) => error?.code === "oauth_unauthorized",
  );
});

test("signs in end to end with an injected terminal", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "anthropic-signin-"));
  const tokenPath = path.join(directory, "token.json");
  const previous = process.env.ANTHROPIC_OAUTH_TOKEN_PATH;
  process.env.ANTHROPIC_OAUTH_TOKEN_PATH = tokenPath;
  const input = new PassThrough();
  const output = new PassThrough();
  let printed = "";
  output.on("data", (chunk) => {
    printed += String(chunk);
  });
  const when = setTimeout(() => input.write("pasted-code\n"), 20);
  try {
    const stored = await signInAnthropic({
      input,
      output,
      open: () => {},
      now: () => 1_700_000_000_000,
      timeoutMs: 5_000,
      fetchImpl: async (url, options) => {
        const body = JSON.parse(options.body);
        assert.equal(body.code, "pasted-code");
        assert.equal(body.grant_type, "authorization_code");
        return {
          ok: true,
          status: 200,
          json: async () => ({
            access_token: "access-token",
            refresh_token: "refresh-token",
            expires_in: 3_600,
          }),
        };
      },
    });
    assert.equal(stored.access_token, "access-token");
    const onDisk = JSON.parse(readFileSync(tokenPath, "utf8"));
    assert.equal(onDisk.access_token, "access-token");
    assert.match(printed, /Sign in to Claude/);
  } finally {
    clearTimeout(when);
    if (previous === undefined) delete process.env.ANTHROPIC_OAUTH_TOKEN_PATH;
    else process.env.ANTHROPIC_OAUTH_TOKEN_PATH = previous;
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a pasted code from another sign-in attempt", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const timer = setTimeout(() => input.write("some-code#not-the-state\n"), 20);
  try {
    await assert.rejects(
      signInAnthropic({
        input,
        output,
        open: () => {},
        timeoutMs: 5_000,
        fetchImpl: async () => {
          throw new Error("should not run");
        },
      }),
      /different sign-in attempt/,
    );
  } finally {
    clearTimeout(timer);
  }
});

test("refuses a non-interactive stdin", async () => {
  await assert.rejects(signInAnthropic({ open: () => {} }), /interactive/);
});
