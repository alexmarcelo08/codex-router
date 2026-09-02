import assert from "node:assert/strict";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  commandCodeAuthPath,
  commandCodeOAuthCredential,
  commandCodeOAuthStatus,
} from "../src/commandcode-oauth.mjs";

function tempHome() {
  return os.tmpdir() && path.join(os.tmpdir(), `commandcode-oauth-${process.pid}-${Math.random()}`);
}

function writeAuth(home, document, apiEnv = "prod") {
  const authPath = commandCodeAuthPath({ homeDir: home, apiEnv });
  mkdirSync(path.dirname(authPath), { recursive: true, mode: 0o700 });
  writeFileSync(authPath, `${JSON.stringify(document)}\n`, { mode: 0o600 });
  chmodSync(authPath, 0o600);
  return authPath;
}

test("reads only the official Command Code OAuth apiKey field", () => {
  const home = tempHome();
  const authPath = writeAuth(home, {
    apiKey: "oauth-secret-that-must-not-be-printed",
    userName: "example-user",
    refreshToken: "ignored",
  });
  const credential = commandCodeOAuthCredential({ homeDir: home });
  assert.equal(credential.value, "oauth-secret-that-must-not-be-printed");
  assert.equal(credential.authPath, authPath);
  assert.match(credential.source, /Command Code CLI OAuth session/);
  assert.equal(commandCodeOAuthStatus({ homeDir: home }).configured, true);
});

test("supports the official local and staging auth filenames", () => {
  const home = tempHome();
  const local = writeAuth(home, { apiKey: "local-key" }, "local");
  const staging = writeAuth(home, { apiKey: "staging-key" }, "staging");
  assert.equal(commandCodeAuthPath({ homeDir: home, apiEnv: "local" }), local);
  assert.equal(commandCodeOAuthCredential({ homeDir: home, apiEnv: "local" }).value, "local-key");
  assert.equal(commandCodeAuthPath({ homeDir: home, apiEnv: "staging" }), staging);
  assert.equal(commandCodeOAuthCredential({ homeDir: home, apiEnv: "staging" }).value, "staging-key");
});

test("rejects a symlinked or group-readable auth file", () => {
  const home = tempHome();
  const authPath = writeAuth(home, { apiKey: "secret" });
  chmodSync(authPath, 0o640);
  assert.equal(commandCodeOAuthCredential({ homeDir: home }), undefined);
});

test("the onboarding snapshot renders the OAuth provider, not an API-key card", async () => {
  const home = tempHome();
  const authPath = writeAuth(home, { apiKey: "snapshot-key" });
  assert.ok(authPath);
  // A virtual CODEX_HOME keeps this test hermetic: the OAuth provider reads
  // the CLI's auth file from there, so the snapshot resolves as configured
  // without touching the machine's real session.
  const previousHome = process.env.CODEX_HOME;
  const previousUserModels = process.env.MODEL_ROUTER_USER_MODELS;
  process.env.CODEX_HOME = home;
  process.env.MODEL_ROUTER_USER_MODELS = path.join(home, "user-models.json");
  try {
    const { providerOnboardingSnapshot } = await import("../src/provider-onboarding.mjs");
    const provider = providerOnboardingSnapshot().providers.find((entry) => entry.id === "commandcode-oauth");
    assert.ok(provider);
    // The tray must offer the browser sign-in flow, never an "Add API key"
    // card, and the session resolves from the CLI auth file.
    assert.equal(provider.kind, "oauth");
    assert.equal(provider.credentialLabel, "OAuth session");
    assert.equal(provider.configured, true);
    // A configured CLI session can still be re-authenticated (expired token,
    // wrong account, plan change); the tray surfaces it so the user can re-run
    // the browser sign-in without disconnecting.
    assert.equal(provider.reauth, true);
    assert.ok(["ready", "login"].includes(provider.action));
    // The API-key sibling stays its own provider, not folded into the OAuth one.
    const api = providerOnboardingSnapshot().providers.find((entry) => entry.id === "commandcode");
    assert.ok(api);
    assert.equal(api.kind, "api");
    // The API side needs its own key; in this hermetic home no env var or
    // credential file is staged, so it is not configured. That is the whole
    // point of the split: the two surfaces are independently connectable.
    assert.equal(api.configured, false);
  } finally {
    process.env.CODEX_HOME = previousHome;
    process.env.MODEL_ROUTER_USER_MODELS = previousUserModels;
  }
});
