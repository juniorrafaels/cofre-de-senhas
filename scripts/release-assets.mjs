#!/usr/bin/env node
// Reúne os instaladores reais gerados pelo `tauri build`, padroniza os nomes (sem espaços), calcula
// o SHA-256 e grava o SHA256SUMS.txt (sempre LF).
//
// Uso: node scripts/release-assets.mjs --tag vX.Y.Z[-beta.N] --bundle-dir <dir> --out-dir <dir>
//      node scripts/release-assets.mjs --from-manifests --bundle-dir <dir> --out-dir <dir>
//        (--from-manifests: sem tag, usa a versão de tauri.conf.json; usado pelo CI manual)
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expectedVersionsFromManifests, parseTag, prepareReleaseAssets } from './release-lib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};

try {
  const bundleDir = option('--bundle-dir');
  const outDir = option('--out-dir');
  if (!bundleDir || !outDir) throw new Error('Informe --bundle-dir e --out-dir.');
  let expected;
  if (args.includes('--from-manifests')) {
    expected = expectedVersionsFromManifests(root);
  } else {
    const parsed = parseTag(option('--tag'));
    expected = { version: parsed.version, wixVersion: parsed.wixVersion };
  }
  const { entries, manifest } = prepareReleaseAssets({
    bundleDir: path.resolve(bundleDir),
    outDir: path.resolve(outDir),
    ...expected,
  });
  console.log(`Arquivos preparados em ${outDir}:`);
  for (const entry of entries) console.log(`  ${entry.name}`);
  console.log('\nSHA256SUMS.txt:');
  process.stdout.write(manifest);
} catch (error) {
  console.error(`::error::${error.message}`);
  process.exit(1);
}
