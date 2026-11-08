import fs from 'node:fs';
import path from 'node:path';

const PLACEHOLDER_PREFIX = 'openshell:resolve:env:';

function* filesUnder(root: string): Generator<string> {
  if (!fs.existsSync(root)) return;
  const stat = fs.statSync(root);
  if (stat.isFile()) {
    yield root;
    return;
  }
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const child = path.join(root, entry.name);
    if (entry.isDirectory()) yield* filesUnder(child);
    else if (entry.isFile()) yield child;
  }
}

/** Replace staged copies of known credentials before they enter the sandbox. */
export function redactCredentialFiles(root: string, credentials: Record<string, string>): void {
  const secrets = Object.entries(credentials)
    .filter(([, value]) => value.length >= 8)
    .sort((a, b) => b[1].length - a[1].length);
  if (secrets.length === 0) return;

  for (const file of filesUnder(root)) {
    const original = fs.readFileSync(file);
    const content = original.toString('utf8');
    if (!Buffer.from(content, 'utf8').equals(original)) continue; // Leave binary assets intact.
    let redacted = content;
    for (const [key, value] of secrets) {
      redacted = redacted.split(value).join(`${PLACEHOLDER_PREFIX}${key}`);
    }
    if (redacted !== content) fs.writeFileSync(file, redacted, { mode: fs.statSync(file).mode });
  }
}

/** Fail before upload if a known host credential is present in the workspace. */
export function assertNoCredentialLeak(root: string, credentials: Record<string, string>): void {
  const secrets = Object.entries(credentials).filter(([, value]) => value.length >= 8);
  for (const file of filesUnder(root)) {
    let content: Buffer;
    try {
      content = fs.readFileSync(file);
    } catch {
      continue;
    }
    for (const [, value] of secrets) {
      if (content.indexOf(Buffer.from(value, 'utf8')) !== -1) {
        throw new Error(`Credential leakage scan blocked upload of ${path.relative(root, file)}`);
      }
    }
  }
}
