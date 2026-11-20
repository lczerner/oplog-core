#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Software bill of materials (SBOM) from package-lock.json, with the npm built-in `npm sbom`.
//
//   sbom/runtime.<ext>.json  the packages that an app gets with oplog-core (no dev dependencies)
//   sbom/build.<ext>.json    all packages, including the build and test toolchain
//
// Usage: node scripts/sbom.mjs [cyclonedx|spdx]   (default: cyclonedx)
//
// Check (exit 1 on a failure): oplog-core has no runtime dependencies (AGENTS.md). The runtime
// SBOM must contain no package. A new runtime dependency needs the owner's approval, and then
// this check must change in the same pull request.
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const format = process.argv[2] ?? 'cyclonedx';
if (!['cyclonedx', 'spdx'].includes(format)) {
  console.error('usage: sbom.mjs [cyclonedx|spdx]');
  process.exit(2);
}
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const sbom = (fmt) => JSON.parse(execFileSync(npm, ['sbom', '--package-lock-only', '--sbom-format', fmt], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }));
const isDev = (c) => (c.properties ?? []).some((p) => p.name === 'cdx:npm:package:development' && p.value === 'true');
const rootIdsOf = (doc) => new Set((doc.relationships ?? []).filter((r) => r.relationshipType === 'DESCRIBES').map((r) => r.relatedSpdxElement));

const cdx = sbom('cyclonedx');
const runtimeComps = cdx.components.filter((c) => !isDev(c));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
if (Object.keys(pkg.dependencies ?? {}).length || runtimeComps.length) {
  console.error(`SBOM check failed: oplog-core must have no runtime dependencies, found: ${[...new Set([...Object.keys(pkg.dependencies ?? {}), ...runtimeComps.map((c) => c.name)])].join(', ')}`);
  process.exit(1);
}

let full;
let runtime;
let ext;
if (format === 'cyclonedx') {
  ext = 'cdx';
  full = cdx;
  const root = cdx.metadata.component['bom-ref'];
  // Each document has its own identifier (CycloneDX serialNumber).
  runtime = { ...cdx, serialNumber: `urn:uuid:${randomUUID()}`, components: [], dependencies: (cdx.dependencies ?? []).filter((d) => d.ref === root).map((d) => ({ ...d, dependsOn: [] })) };
} else {
  ext = 'spdx';
  full = sbom('spdx');
  const keep = rootIdsOf(full);
  keep.add(full.SPDXID);
  runtime = {
    ...full,
    name: `${full.name} (runtime)`,
    // Each document has its own identifier (SPDX documentNamespace).
    documentNamespace: `${full.documentNamespace}-runtime`,
    packages: full.packages.filter((p) => keep.has(p.SPDXID)),
    relationships: (full.relationships ?? []).filter((r) => keep.has(r.spdxElementId) && keep.has(r.relatedSpdxElement)),
  };
}

mkdirSync('sbom', { recursive: true });
for (const [name, doc] of [['runtime', runtime], ['build', full]]) {
  const path = `sbom/${name}.${ext}.json`;
  writeFileSync(path, JSON.stringify(doc, null, 2) + '\n');
  const n = format === 'cyclonedx' ? doc.components.length : doc.packages.filter((p) => !rootIdsOf(doc).has(p.SPDXID)).length;
  console.log(`${path}: ${n} packages`);
}
