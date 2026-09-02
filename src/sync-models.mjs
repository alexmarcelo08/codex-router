#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";

import { discoverProviderModels } from "./model-discovery.mjs";
import {
  curatedModelContextLength,
  curatedModelProviderId,
  curatedModelReasoningLevels,
} from "./opencode-curation.mjs";
import { curationProviderIds } from "./opencode-curation.mjs";
import { readUserModels, writeUserModels } from "./user-models.mjs";
import { userModelEntry } from "./user-models.mjs";
import { setModelsVisible } from "./model-picker-state.mjs";
import { CHECKED_IN_MODELS } from "./model-registry.mjs";
import {
  applyModelOverlayPublication,
  transactModelOverlayMutation,
} from "./model-overlay-publication.mjs";
import { USER_MODELS_PATH } from "./user-models.mjs";

const DEFAULT_CONTEXT = 131072;
const BASE_PRIORITY = 100;

function metadataFor(providerId, id, contextWindow) {
  const metadata = {};
  if (contextWindow) {
    metadata.contextWindow = contextWindow;
    metadata.autoCompact = Math.round(contextWindow * 0.85);
  }
  const ladder = curatedModelReasoningLevels(providerId, id);
  if (ladder && ladder.length) metadata.reasoningLevels = ladder;
  return metadata;
}

function buildEntry({ providerId, upstreamId, priority, metadata }) {
  const routedProviderId = curatedModelProviderId(providerId, upstreamId);
  return userModelEntry({
    providerId: routedProviderId,
    upstreamId,
    priority,
    metadata,
  });
}

function planSync({ mine, addable, removedIds, providerIds }) {
  const providerSet = new Set(providerIds);
  const byUpstream = new Map(mine.map((m) => [m.upstreamModel, m]));
  // A checked-in registry model is always kept. Only an entry that exists *only*
  // in the operator's user-models overlay and is no longer advertised is a prune
  // candidate; an identifier that also resolves to a shipped route is ignored.
  const checkedInUpstreams = new Set(CHECKED_IN_MODELS.map((m) => m.upstreamModel));
  const removals = removedIds.filter(
    (id) => byUpstream.has(id) && !checkedInUpstreams.has(id),
  );
  const missing = new Set(removals);
  const kept = mine.filter((m) => !missing.has(m.upstreamModel));
  const existingUpstreams = new Set(kept.map((m) => m.upstreamModel));
  const additions = addable.filter(
    (id) => !existingUpstreams.has(id) && providerSet.has(curatedModelProviderId(providerId, id)),
  );
  return { kept, additions, removals };
}

async function main() {
  const argv = process.argv.slice(2);
  const help = argv.includes("--help");
  const refresh = argv.includes("--refresh");
  const noApply = argv.includes("--no-apply");
  const dryRun = argv.includes("--dry-run");
  const prune = argv.includes("--prune");
  const explicitProviders = argv.filter((a) => !a.startsWith("--"));

  if (help) {
    process.stdout.write(
      "Usage: sync-models [PROVIDER ...] [--refresh] [--dry-run] [--no-apply] [--prune]\n\n" +
        "Auto-sync locally curated models against each provider's live /v1/models catalog.\n" +
        "Adds newly advertised models whose route is settled. Checked-in registry models are\n" +
        "never touched. --prune also removes locally curated models the provider no longer\n" +
        "advertises (off by default to avoid dropping a deliberately curated model).\n\n" +
        "--refresh   Re-ask providers instead of reading the cached catalog.\n" +
        "--dry-run   Report what would change without writing anything.\n" +
        "--no-apply  Write user-models.json but do not rebuild routes.\n" +
        "--prune     Remove locally curated models the provider no longer advertises.\n",
    );
    return;
  }

  const { PROVIDERS } = await import("./model-registry.mjs");
  const providerSelection = await import("./provider-selection.mjs");
  const enabled = explicitProviders.length
    ? explicitProviders
    : providerSelection.readProviderSelection();
  const enabledSet = new Set(enabled);

  const current = readUserModels();
  let added = [];
  let removed = [];
  let blocked = {};
  const reports = [];

  for (const providerId of enabled) {
    if (!PROVIDERS.has(providerId)) {
      reports.push(`${providerId}: unknown provider, skipped`);
      continue;
    }
    let discovery;
    try {
      discovery = await discoverProviderModels(providerId, { refresh });
    } catch (error) {
      reports.push(`${providerId}: ${error instanceof Error ? error.message : String(error)}`);
      continue;
    }
    const addable = discovery.addable || [];
    const blockedForProvider = discovery.blocked || {};
    const advertised = new Set(discovery.discovered || []);
    const registeredProviderIds = curationProviderIds(providerId);
    const locallyCurated = current.filter((m) => registeredProviderIds.includes(m.provider));
    const disappear = locallyCurated
      .map((m) => m.upstreamModel)
      .filter((id) => !advertised.has(id));
    const plan = planSync({
      mine: locallyCurated,
      addable,
      removedIds: prune ? disappear : [],
      providerIds: registeredProviderIds,
    });
    added.push(...plan.additions);
    removed.push(...plan.removals);
    for (const [id, reason] of Object.entries(blockedForProvider)) blocked[id] = reason;
    reports.push(
      `${providerId}: +${plan.additions.length} addable, -${plan.removals.length} pruned, ` +
        `${discovery.discovered.length} advertised`,
    );
  }

  const planSummary = {
    providers: enabled,
    wouldAdd: added,
    wouldRemove: removed,
    blocked,
    currentCurated: current.length,
  };
  const summaryText = `${JSON.stringify({ plan: planSummary, reports }, null, 2)}\n`;
  process.stdout.write(summaryText);

  if (dryRun) {
    process.stdout.write("Dry run: nothing was written.\n");
    return;
  }
  if (noApply) {
    process.stdout.write("--no-apply: nothing was written. Omit it to persist.\n");
    return;
  }

  const removeSet = new Set(removed);
  const kept = current.filter((m) => !removeSet.has(m.upstreamModel));
  const existingUpstreams = new Set(kept.map((m) => m.upstreamModel));
  const notAlready = added.filter((id) => !existingUpstreams.has(id));
  let nextPriority = BASE_PRIORITY + kept.length;
  const additions = notAlready.map((id) => {
    const ctx = curatedModelContextLength(enabled[0], id) || DEFAULT_CONTEXT;
    return buildEntry({
      providerId: enabled[0],
      upstreamId: id,
      priority: nextPriority++,
      metadata: metadataFor(enabled[0], id, ctx),
    });
  });
  const nextMine = [...kept, ...additions];
  const newSlugs = additions.map((m) => m.slug);

  await transactModelOverlayMutation({
    files: [USER_MODELS_PATH],
    mutate: () => {
      writeUserModels(nextMine);
      if (newSlugs.length) setModelsVisible(newSlugs, true);
    },
    restart: true,
    applyPublication: async (options) => applyModelOverlayPublication(options),
  });

  process.stdout.write(
    `\nSynced ${enabled.join(", ")}: added ${notAlready.length}, removed ${removed.length}. ` +
      "Fully quit and reopen Codex.\n",
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}
