#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const MANIFEST_PATH = resolve(ROOT, "validation/just-bash/manifest.json");
const EVIDENCE_JSON = resolve(ROOT, "evidence/just-bash-adversarial-20260923.json");
const EVIDENCE_MD = resolve(ROOT, "evidence/just-bash-adversarial-20260923.md");

export function invalidateVerification(reason = "adversarial run started but has not completed", details = {}) {
  const invalidatedAt = new Date().toISOString();
  mkdirSync(dirname(MANIFEST_PATH), { recursive: true });
  mkdirSync(dirname(EVIDENCE_JSON), { recursive: true });
  writeFileSync(EVIDENCE_JSON, `${JSON.stringify({ ...details, status: "unverified", captured_at: invalidatedAt, reason }, null, 2)}\n`);
  writeFileSync(EVIDENCE_MD, `# JustBash adversarial verification\n\n- Overall status: \`unverified\`\n- Run started: \`${invalidatedAt}\`\n- Reason: ${reason}.\n`);

  if (existsSync(MANIFEST_PATH)) {
    let manifest;
    try {
      manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
      manifest.verification = { status: "unverified", adversarial_evidence: [] };
    } catch (error) {
      manifest = {
        invalidated_at: invalidatedAt,
        invalidation_error: error.message,
        verification: { status: "unverified", adversarial_evidence: [] },
      };
    }
    writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  invalidateVerification();
}
