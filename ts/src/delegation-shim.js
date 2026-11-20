#!/usr/bin/env node
// This file is staged into an OpenShell sandbox. It has no host credentials.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const dir = process.env.ORCA_DELEGATION_DIR;
if (!dir || !/^\/tmp\/orca-delegate-[a-f0-9-]{36}$/.test(dir)) {
  console.error('Orca delegation is unavailable in this sandbox');
  process.exit(77);
}
const id = crypto.randomUUID();
const response = path.join(dir, id);
try {
  execFileSync('mkfifo', ['-m', '600', response]);
  const argv = process.argv.slice(2);
  if (argv[0] === 'orchestration' && argv[1] === 'worker-start') {
    const i = argv.indexOf('--spec-file');
    if (i >= 0) {
      const source = argv[i + 1];
      if (!source) throw new Error('--spec-file requires a path or -');
      const spec = fs.readFileSync(source === '-' ? 0 : source, 'utf8');
      argv.splice(i, 2, '--spec', spec);
    }
    const pIdx = argv.indexOf('--policy-file');
    if (pIdx >= 0) {
      const pSource = argv[pIdx + 1];
      if (!pSource) throw new Error('--policy-file requires a path or -');
      const rawPolicy = fs.readFileSync(pSource === '-' ? 0 : pSource, 'utf8');
      const extra = [];
      let parsedJson = null;
      if (rawPolicy.trim().startsWith('{')) {
        parsedJson = JSON.parse(rawPolicy);
      }
      if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
        const rp = parsedJson.readPaths ?? parsedJson.read_paths;
        const wp = parsedJson.writePaths ?? parsedJson.write_paths;
        if (rp !== undefined && !argv.includes('--read-paths')) {
          extra.push('--read-paths', JSON.stringify(rp));
        }
        if (wp !== undefined && !argv.includes('--write-paths')) {
          extra.push('--write-paths', JSON.stringify(wp));
        }
        if (
          parsedJson.network_policies !== undefined ||
          parsedJson.networkPolicies !== undefined ||
          parsedJson.endpoints !== undefined ||
          parsedJson.filesystem_policy !== undefined ||
          parsedJson.filesystemPolicy !== undefined ||
          parsedJson.landlock !== undefined ||
          parsedJson.network_middlewares !== undefined ||
          parsedJson.networkMiddlewares !== undefined ||
          parsedJson.process !== undefined
        ) {
          if (!argv.includes('--openshell-policy')) {
            extra.push('--openshell-policy', JSON.stringify(parsedJson));
          }
        }
      } else if (!argv.includes('--openshell-policy')) {
        extra.push('--openshell-policy', rawPolicy);
      }
      argv.splice(pIdx, 2, ...extra);
    }
  }
  const request = JSON.stringify({ id, argv }) + '\n';
  if (request.length > 65536) throw new Error('Delegation request is too large');
  const lock = path.join(dir, 'write-lock');
  const deadline = Date.now() + 10000;
  while (true) {
    try { fs.mkdirSync(lock); break; }
    catch { if (Date.now() > deadline) throw new Error('Delegation request lock timed out'); }
  }
  try { fs.writeFileSync(path.join(dir, 'requests'), request); }
  finally { fs.rmdirSync(lock); }
  const reply = JSON.parse(execFileSync('cat', [response], { encoding: 'utf8', timeout: 240000, maxBuffer: 2_000_000 }));
  if (typeof reply.stdout === 'string') process.stdout.write(reply.stdout);
  if (typeof reply.stderr === 'string') process.stderr.write(reply.stderr);
  process.exit(Number.isInteger(reply.code) ? reply.code : 1);
} catch (error) {
  console.error(`Orca delegation failed: ${error}`);
  process.exit(1);
} finally {
  try { fs.unlinkSync(response); } catch {}
}
