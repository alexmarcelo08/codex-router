import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  grokCliFailureMessage,
  grokCliPath,
  grokCliPreflight,
} from "./grok-cli.mjs";
import { devinCliStatus } from "./devin-cli-status.mjs";
import { grokOAuthStatus } from "./grok-oauth-status.mjs";
import { antigravityOAuthStatus } from "./antigravity-oauth-status.mjs";
import { removeAntigravityToken } from "./antigravity-oauth-session.mjs";
import { commandCodeOAuthStatus } from "./commandcode-oauth.mjs";
import { KIMI_CLI_NPM_PACKAGE } from "./kimi-oauth-onboarding.mjs";
import { MODELS, PROVIDERS, providerNeedsNoKey } from "./model-registry.mjs";
import {
  forgetProviderCatalogFamilyCache,
  providerCatalogSources,
} from "./provider-catalogs.mjs";
import { curationProviderIds } from "./opencode-curation.mjs";
import { kimiOAuthStatus } from "./oauth-status.mjs";
import {
  apiProvider,
  credentialLabel,
  credentialStatus,
  removeProviderCredential,
  writeProviderCredential,
} from "./provider-credentials.mjs";
import { disableProvider } from "./provider-selection.mjs";
import {
  npmGlobalBinary,
  npmInstallGlobal,
  spawnEnvironment,
} from "./npm-global-install.mjs";
import { commandOnPath, spawnableCommand } from "./spawnable-command.mjs";

const SIGN_IN_CLIS = Object.freeze({
  "kimi-oauth": {
    executable: "kimi",
    npmPackage: KIMI_CLI_NPM_PACKAGE,
    loginArgs: ["login"],
    candidates: [path.join(os.homedir(), ".npm-global", "bin", "kimi")],
  },
  "grok-oauth": {
    executable: "grok",
    npmPackage: "@xai-official/grok",
    loginArgs: ["login", "--oauth"],
  },
  // Devin ships no npm package: it is a Rust binary installed by Cognition's
  // own script or Homebrew cask. `installCommand` is what the tray offers
  // instead of an npm install it cannot perform.
  "devin-cli": {
    executable: "devin",
    loginArgs: ["auth", "login"],
    candidates: [path.join(os.homedir(), ".local", "bin", "devin")],
    installCommand: "curl -fsSL https://cli.devin.ai/install.sh | bash",
    // `devin auth login` draws a full-screen terminal interface, so a piped
    // stdio pair kills it before it opens the browser.
    needsTerminal: true,
  },
  // Command Code's official CLI signs in through its own browser flow and
  // writes `~/.commandcode/auth.json`. Reuse that login instead of asking the
  // operator to paste an OAuth session string.
  commandcode: {
    executable: "command-code",
    loginArgs: ["login"],
    candidates: [path.join(os.homedir(), ".local", "bin", "command-code")],
    installCommand:
      "Command Code is installed by its own installer; install it before signing in.",
  },
});

function commandPath(name) {
  // Not the finder's first line: on Windows that is the extensionless npm
  // shim, and every caller here goes on to spawn what it gets back.
  return commandOnPath(name);
}

export function oauthCliPath(providerId) {
  const cli = SIGN_IN_CLIS[providerId];
  if (!cli) throw new Error(`Unknown OAuth provider: ${providerId}`);
  if (providerId === "grok-oauth") return grokCliPath();
  const discovered = commandPath(cli.executable);
  if (discovered) return discovered;
  const candidate = (cli.candidates || []).find((path) => existsSync(path));
  if (candidate) return candidate;
  // Last resort, because it costs an npm spawn: ask npm where it actually
  // installs global binaries. A custom prefix is invisible to both PATH (the
  // tray's is the bare system one) and to any list of guessed directories.
  return npmGlobalBinary(cli.executable);
}

export function oauthLoginArgs(providerId) {
  const cli = SIGN_IN_CLIS[providerId];
  if (!cli) throw new Error(`Unknown OAuth provider: ${providerId}`);
  return [...cli.loginArgs];
}

function oauthConfigured(providerId) {
  if (providerId === "kimi-oauth") return kimiOAuthStatus().configured;
  if (providerId === "grok-oauth") return grokOAuthStatus().configured;
  if (providerId === "antigravity-oauth") return antigravityOAuthStatus().configured;
  if (providerId === "devin-cli") return devinCliStatus().configured;
  if (providerId === "commandcode") return commandCodeOAuthStatus().configured;
  return false;
}

export function providerOnboardingSnapshot() {
  // Protocol variants share their parent's key and selection, so onboarding
  // surfaces (tray, guided setup) offer one entry per family.
  const selectable = [...PROVIDERS.values()].filter((provider) => !provider.variantOf);
  return {
    providers: selectable.map((provider) => {
      const catalogSources = providerCatalogSources(provider.id);
      // Command Code's OAuth provider is an openai-compatible endpoint that
      // authenticates with the sign-in the official CLI already performed.
      // The tray must offer that browser login (and never an "Add API key"
      // card), so selectable providers that carry a CLI session render through
      // the OAuth path even though their `kind` stays openai-compatible.
      if (provider.credential?.cliSession === true) {
        const cliPath = oauthCliPath(provider.id);
        const cliInstalled = Boolean(cliPath);
        const configured = oauthConfigured(provider.id);
        return {
          id: provider.id,
          displayName: provider.displayName,
          kind: "oauth",
          credentialLabel: "OAuth session",
          configured,
          cliInstalled,
          cliRunnable: cliInstalled,
          // A configured session can still be re-authenticated (an expired
          // token, a wrong account, or a plan change); surface it so the UI
          // can offer "Re-authenticate" instead of only "ready".
          reauth: configured ? true : false,
          action: !cliInstalled
            ? "install"
            : configured
              ? "ready"
              : "login",
          ...(catalogSources.length ? { catalogSources } : {}),
          ...(provider.planNote ? { planNote: provider.planNote } : {}),
        };
      }
      if (provider.kind === "oauth") {
        // Antigravity has no vendor CLI to install or reuse: its sign-in is
        // this router's own browser OAuth flow.
        if (provider.id === "antigravity-oauth") {
          const status = antigravityOAuthStatus();
          const configured = status.configured;
          return {
            id: provider.id,
            displayName: provider.displayName,
            kind: "oauth",
            credentialLabel: "OAuth session",
            configured,
            // A rejected or damaged session is not configured, but its
            // router-managed file must remain removable from every UI.
            disconnectable: status.credentialPresent,
            cliInstalled: true,
            cliRunnable: true,
            action: configured ? "ready" : "login",
            ...(catalogSources.length ? { catalogSources } : {}),
          };
        }
        const cliPath = oauthCliPath(provider.id);
        const cli = provider.id === "grok-oauth"
          ? grokCliPreflight({ executable: cliPath })
          : { installed: Boolean(cliPath), runnable: Boolean(cliPath) };
        const cliInstalled = cli.installed;
        const configured = oauthConfigured(provider.id);
        return {
          id: provider.id,
          displayName: provider.displayName,
          kind: "oauth",
          configured,
          cliInstalled,
          cliRunnable: cli.runnable,
          action: !cliInstalled
            ? "install"
            : !cli.runnable
              ? "blocked"
              : configured
                ? "ready"
                : "login",
          ...(catalogSources.length ? { catalogSources } : {}),
        };
      }
      const configured = providerNeedsNoKey(provider)
        ? true
        : credentialStatus(provider, { persistent: true }).configured;
      const entry = {
        id: provider.id,
        displayName: provider.displayName,
        kind: "api",
        ...(provider.credential?.label ? { credentialLabel: credentialLabel(provider) } : {}),
        configured,
        action: configured ? "ready" : "add-key",
        ...(catalogSources.length ? { catalogSources } : {}),
        // Carried to the tray so the plan requirement is visible at the
        // moment someone decides to connect, not after Codex 403s.
        ...(provider.planNote ? { planNote: provider.planNote } : {}),
      };
      // A container has no key field of its own. Saying so is the whole card:
      // an "Add Key" button here would store a secret nothing ever reads.
      if (provider.authMode === "per-model") {
        entry.kind = "per-model";
        entry.action = "per-model";
        entry.credentialLabel = "Per-model endpoints";
        entry.perModelNote =
          "Each model here names its own endpoint and its own auth. Enabling this provider costs nothing.";
        return entry;
      }
      if (provider.authMode === "anonymous") {
        entry.kind = "anonymous";
        // Guided setup pre-checks every `ready` row. An off-box endpoint must
        // be chosen explicitly even though it needs no API key.
        entry.action = "anonymous";
        entry.credentialLabel = "No API key";
        entry.anonymousNote = provider.anonymousNote;
        return entry;
      }
      return entry;
    }),
  };
}

// npm and every CLI it installs globally start with `#!/usr/bin/env node`, so
// they die instantly unless node is on PATH. The tray is launched by launchd
// with the bare system PATH, which has no node on it — the failure there was
// `env: node: No such file or directory` behind a generic "could not install".
// Whatever node is running this file is by definition a working one, so put
// its directory in front for the child.
export function installOauthCli(providerId) {
  const cli = SIGN_IN_CLIS[providerId];
  if (!cli) throw new Error(`Unknown OAuth provider: ${providerId}`);
  if (providerId === "grok-oauth") {
    const preflight = grokCliPreflight();
    if (preflight.installed) {
      if (!preflight.runnable) throw new Error(grokCliFailureMessage(preflight));
      return;
    }
  } else if (oauthCliPath(providerId)) {
    return;
  }
  // Not every official CLI is an npm package. Naming the vendor's own
  // installer is honest; running it unattended from the tray would fetch and
  // execute a remote script the operator never saw.
  if (!cli.npmPackage) {
    throw new Error(
      `The ${cli.executable} CLI is not installed and is not distributed through npm. Install it with: ${cli.installCommand}`,
    );
  }
  npmInstallGlobal(cli.npmPackage, { label: `the official ${cli.executable} CLI` });
  if (providerId === "grok-oauth") {
    const preflight = grokCliPreflight();
    if (!preflight.runnable) throw new Error(grokCliFailureMessage(preflight));
  } else if (!oauthCliPath(providerId)) {
    // The install reported success, so the binary exists somewhere npm knows
    // about and this router does not. Name the search so it is fixable.
    throw new Error(
      `npm installed ${cli.npmPackage}, but no \`${cli.executable}\` was found on PATH or in npm's global bin directory.`,
    );
  }
}

// A browser sign-in is slow by nature — the operator has to switch apps, log
// in, and authorize — but it must not be able to wedge the tray forever if the
// CLI waits on a terminal it will never get.
const LOGIN_TIMEOUT_MS = 10 * 60_000;

export async function loginOauthProvider(providerId) {
  if (providerId === "antigravity-oauth") {
    const { signInAntigravity } = await import("./antigravity-oauth-onboarding.mjs");
    await signInAntigravity();
    if (!oauthConfigured(providerId)) {
      throw new Error("Sign-in finished without a usable Antigravity OAuth session. Please try again.");
    }
    if (providerCatalogSources(providerId).length) {
      await forgetProviderCatalogFamilyCache(providerId);
    }
    return;
  }
  const executable = oauthCliPath(providerId);
  if (!executable) throw new Error("Install the provider CLI before signing in.");
  if (providerId === "grok-oauth") {
    const preflight = grokCliPreflight({ executable });
    if (!preflight.runnable) throw new Error(grokCliFailureMessage(preflight));
  }
  // The CLI itself is another `#!/usr/bin/env node` script, so signing in needs
  // the same PATH repair the install did.
  const login = spawnableCommand(executable, oauthLoginArgs(providerId));
  const result = spawnSync(login.command, login.args, {
    ...login.options,
    encoding: "utf8",
    env: spawnEnvironment(),
    timeout: LOGIN_TIMEOUT_MS,
  });
  // A sign-in the operator never finished and one the CLI could not run look
  // the same from here, so say both are possible rather than blaming them.
  if (result.signal === "SIGTERM") {
    throw new Error(
      `${executable} did not finish signing in within 10 minutes. Run it in a terminal to see what it is waiting for.`,
    );
  }
  if (result.error || result.status !== 0) {
    // Carry the CLI's own last line: a cancelled sign-in and a CLI that could
    // not start look identical without it.
    throw new Error(
      `Provider sign-in was cancelled or did not complete. ${installFailureDetail(result)}`.trim(),
    );
  }
  if (!oauthConfigured(providerId)) {
    throw new Error("Sign-in finished without a usable OAuth session. Please try again.");
  }
  if (providerCatalogSources(providerId).length) {
    await forgetProviderCatalogFamilyCache(providerId);
  }
}

export function saveApiCredential(providerId, value) {
  writeProviderCredential(providerId, value);
}

// Deleting the managed key files cannot reach a key that also lives in the
// macOS Keychain or the environment, so report what still resolves afterwards
// instead of claiming the credential itself is gone.
export async function removeApiCredential(providerId) {
  if (providerId === "antigravity-oauth") {
    const provider = PROVIDERS.get(providerId);
    const removedFiles = (await removeAntigravityToken()) ? 1 : 0;
    // Disconnect is also a routing decision. Withdraw the provider even when
    // the credential vanished between the snapshot and this action.
    disableProvider(providerId);
    const remaining = antigravityOAuthStatus();
    return {
      provider: providerId,
      displayName: provider?.displayName || "Google Antigravity OAuth",
      removedFiles,
      stillConfigured: remaining.configured === true,
      remainingSource: remaining.configured ? remaining.source : undefined,
    };
  }
  const provider = apiProvider(providerId);
  const removedFiles = removeProviderCredential(provider);
  if (removedFiles) disableProvider(provider.id);
  const remaining = credentialStatus(provider, { persistent: true });
  return {
    provider: provider.id,
    displayName: provider.displayName,
    removedFiles,
    stillConfigured: remaining.configured === true,
    remainingSource: remaining.configured ? remaining.source : undefined,
  };
}

// Command Code's OAuth session is owned by the official CLI, not by a
// router-managed file. The generic credential removal cannot reach it --
// `credentialPaths` returns [] for a cliSession provider -- so a real logout
// has to drive the CLI's own `logout`, then withdraw the provider from the
// router so no model still routes to a dead session.
export async function logoutCommandCode() {
  const provider = PROVIDERS.get("commandcode");
  const cliPath = oauthCliPath("commandcode");
  let cliRan = false;
  let cliMessage;
  if (cliPath) {
    try {
      const result = spawnSync(cliPath, ["logout"], { encoding: "utf8" });
      cliRan = true;
      const stdout = String(result?.stdout || "").trim();
      const stderr = String(result?.stderr || "").trim();
      cliMessage = stdout || stderr || undefined;
      if (result && result.status !== 0) {
        cliMessage = `command-code logout exited ${result.status}: ${cliMessage || "unknown error"}`;
      }
    } catch (error) {
      cliMessage = `command-code logout failed: ${error?.message || String(error)}`;
    }
  } else {
    cliMessage = "Command Code CLI not found; the OAuth session must be cleared manually.";
  }
  // Withdraw the provider regardless so the router stops advertising its models.
  disableProvider("commandcode");
  const status = commandCodeOAuthStatus();
  return {
    provider: "commandcode",
    displayName: provider?.displayName || "Command Code OAuth",
    cliRan,
    cliMessage,
    stillConfigured: status.configured === true,
    remainingSource: status.configured ? status.source : undefined,
  };
}

// Catalog-only providers (gemini-api, openrouter, groq, ...) ship no
// preselected models, so a stored key still leaves the picker empty. Callers
// use this to name the curation step instead of reporting a provider that
// looks enabled but shows nothing.
export function providerNeedsCuration(providerId, models = MODELS) {
  const providers = new Set(curationProviderIds(providerId));
  return !models.some((model) => providers.has(model.provider));
}
