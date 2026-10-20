#!/usr/bin/env node
// Valida a tag de release contra as versões do projeto (usado pelo job "Validar tag" do
// release.yml). Uso: node scripts/release-check-version.mjs vX.Y.Z[-beta.N]
// Em caso de sucesso, escreve version/prerelease/wix_version em $GITHUB_OUTPUT (se definido).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkVersions, parseTag } from './release-lib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tag = process.argv[2];

try {
  const parsed = parseTag(tag);
  const errors = checkVersions(root, parsed);
  if (errors.length > 0) {
    for (const error of errors) console.error(`::error::${error}`);
    process.exit(1);
  }
  console.log(`Tag ${tag} confere com os manifestos (versão ${parsed.version}, ${parsed.prerelease ? 'beta' : 'estável'}).`);
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(
      process.env.GITHUB_OUTPUT,
      `version=${parsed.version}\nprerelease=${parsed.prerelease}\nwix_version=${parsed.wixVersion ?? ''}\n`,
    );
  }
} catch (error) {
  console.error(`::error::${error.message}`);
  process.exit(1);
}
