// Command Code's official CLI has a browser sign-in flow, but the credential
// it receives is intentionally an API key.  Keep the OAuth integration small:
// the router delegates the browser exchange to the official CLI and reads only
// the documented `apiKey` field from its protected auth file.  It never copies
// or rewrites that file, and it never logs the value.

import { existsSync, lstatSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const AUTH_FILE_NAMES = Object.freeze({
  local: "auth.local.json",
  staging: "auth.staging.json",
  prod: "auth.json",
});

function apiEnvironment(environment = process.env) {
  const value = String(environment.COMMANDCODE_API_ENV || "").trim().toLowerCase();
  return value === "local" || value === "staging" ? value : "prod";
}

export function commandCodeAuthPath({ homeDir, apiEnv } = {}) {
  const fileName = AUTH_FILE_NAMES[apiEnv || apiEnvironment()] || AUTH_FILE_NAMES.prod;
  // Honor a virtual CODEX_HOME (used by hermetic tests and by tools that keep
  // Codex state elsewhere) the same way the rest of the router's paths do.
  // Falling back to the real home keeps the production case unchanged.
  const base = homeDir || process.env.CODEX_HOME || os.homedir();
  return path.join(base, ".commandcode", fileName);
}

function safeAuthDocument(authPath) {
  if (!existsSync(authPath)) return undefined;
  try {
    // The official CLI writes a regular 0600 file beneath a directory that is
    // usually 0700 but, on a default macOS home, is 0755 (`~` itself is 0755).
    // Reject links and group/world-*writable* files before touching the JSON so
    // a redirected path can never turn this into an accidental secret reader.
    const directory = lstatSync(path.dirname(authPath));
    if (!directory.isDirectory() || directory.isSymbolicLink()) return undefined;
    if (process.platform !== "win32" && (directory.mode & 0o002) !== 0) return undefined;
    const info = lstatSync(authPath);
    if (!info.isFile() || info.isSymbolicLink()) return undefined;
    if (process.platform !== "win32" && (info.mode & 0o077) !== 0) return undefined;
    const value = JSON.parse(readFileSync(authPath, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

export function commandCodeOAuthCredential(options = {}) {
  const authPath = commandCodeAuthPath(options);
  const document = safeAuthDocument(authPath);
  const value = typeof document?.apiKey === "string" ? document.apiKey.trim() : "";
  if (!value) return undefined;
  return {
    value,
    source: `Command Code CLI OAuth session (${authPath})`,
    persistent: true,
    authPath,
  };
}

export function commandCodeOAuthStatus(options = {}) {
  const authPath = commandCodeAuthPath(options);
  const credential = commandCodeOAuthCredential(options);
  return credential
    ? { configured: true, source: credential.source, authPath }
    : { configured: false, authPath };
}
