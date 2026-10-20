// Regras de versão, nomes e checksums da release automatizada (.github/workflows/release.yml).
// Funções puras e testáveis (scripts/__tests__/release.test.mjs); os CLIs ficam em
// release-check-version.mjs e release-assets.mjs.
//
// DECISÃO DE VERSIONAMENTO (docs/RELEASE.md, "Versões beta"):
//  - Tags aceitas: vMAJOR.MINOR.PATCH (estável) e vMAJOR.MINOR.PATCH-beta.N (N >= 1). Outros
//    sufixos (rc, alpha...) são recusados de propósito: o MSI não representa texto de pré-release.
//  - package.json, tauri.conf.json e Cargo.toml carregam a versão EXATA da tag (ex.: 0.1.0-beta.2),
//    então NSIS e o app mostram a versão completa e dois betas nunca têm o mesmo nome.
//  - O MSI (WiX) só aceita versão numérica: para betas, bundle.windows.wix.version precisa ser
//    MAJOR.MINOR.PATCH.N (ex.: 0.1.0.2). Versão estável não define wix.version.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MANIFEST_NAME = 'SHA256SUMS.txt';

const TAG_RE = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-beta\.([1-9]\d*))?$/;
const SAFE_ASSET_NAME_RE = /^[A-Za-z0-9._-]+$/;
const MANIFEST_LINE_RE = /^([0-9a-f]{64}) {2}([A-Za-z0-9._-]+)$/;

export function parseTag(tag) {
  const match = TAG_RE.exec(tag ?? '');
  if (!match) {
    throw new Error(
      `Tag '${tag}' inválida. Use vMAJOR.MINOR.PATCH (estável) ou vMAJOR.MINOR.PATCH-beta.N (beta, N >= 1).`,
    );
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  const beta = match[4] === undefined ? null : Number(match[4]);
  // Limites do Windows Installer / WiX (ver tauri-bundler: validate_wix_version).
  if (major > 255 || minor > 255) throw new Error('MAJOR e MINOR não podem passar de 255 (limite do MSI).');
  if (patch > 65535) throw new Error('PATCH não pode passar de 65535 (limite do MSI).');
  if (beta !== null && beta > 65535) throw new Error('N do beta não pode passar de 65535 (limite do MSI).');
  const core = `${major}.${minor}.${patch}`;
  return {
    tag,
    version: beta === null ? core : `${core}-beta.${beta}`,
    major,
    minor,
    patch,
    beta,
    prerelease: beta !== null,
    wixVersion: beta === null ? null : `${core}.${beta}`,
  };
}

export function readCargoPackageVersion(cargoToml) {
  let inPackage = false;
  for (const line of cargoToml.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[')) {
      inPackage = trimmed === '[package]';
      continue;
    }
    if (inPackage) {
      const match = /^version\s*=\s*"([^"]+)"/.exec(trimmed);
      if (match) return match[1];
    }
  }
  return null;
}

export function readManifestVersions(root) {
  const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
  const tauriConf = readJson('src-tauri/tauri.conf.json');
  return {
    packageJson: readJson('package.json').version ?? null,
    tauriConf: tauriConf.version ?? null,
    cargoToml: readCargoPackageVersion(fs.readFileSync(path.join(root, 'src-tauri/Cargo.toml'), 'utf8')),
    wix: tauriConf.bundle?.windows?.wix?.version ?? null,
  };
}

/** Confere se os manifestos do projeto batem com a tag. Devolve a lista de erros (vazia = ok). */
export function checkVersions(root, parsedTag) {
  const found = readManifestVersions(root);
  const errors = [];
  for (const [label, value] of [
    ['package.json', found.packageJson],
    ['src-tauri/tauri.conf.json', found.tauriConf],
    ['src-tauri/Cargo.toml', found.cargoToml],
  ]) {
    if (value !== parsedTag.version) {
      errors.push(
        `${label} tem a versão '${value}', mas a tag ${parsedTag.tag} exige exatamente '${parsedTag.version}'.`,
      );
    }
  }
  if (parsedTag.prerelease) {
    if (found.wix !== parsedTag.wixVersion) {
      errors.push(
        `Beta exige bundle.windows.wix.version = '${parsedTag.wixVersion}' em src-tauri/tauri.conf.json ` +
          `(o MSI só aceita versão numérica); encontrado: ${found.wix === null ? '(ausente)' : `'${found.wix}'`}.`,
      );
    }
  } else if (found.wix !== null) {
    errors.push(
      `Versão estável não deve definir bundle.windows.wix.version (encontrado '${found.wix}'): remova-o de src-tauri/tauri.conf.json.`,
    );
  }
  return errors;
}

/** Versão esperada nos nomes dos instaladores, lida dos manifestos (uso fora de uma tag, ex.: CI manual). */
export function expectedVersionsFromManifests(root) {
  const found = readManifestVersions(root);
  return { version: found.tauriConf, wixVersion: found.wix };
}

export function sanitizeAssetName(name) {
  const safe = name.trim().replace(/\s+/g, '-');
  if (!SAFE_ASSET_NAME_RE.test(safe)) {
    throw new Error(`Nome de instalador inesperado: '${name}'. Depois de trocar espaços por '-', só são aceitos A-Z a-z 0-9 . _ -`);
  }
  return safe;
}

function listFiles(dir, predicate) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && predicate(entry.name))
    .map((entry) => path.join(dir, entry.name));
}

/** Localiza exatamente um .msi e um -setup.exe gerados pelo Tauri em <bundleDir>/{msi,nsis}. */
export function findInstallers(bundleDir) {
  const msi = listFiles(path.join(bundleDir, 'msi'), (n) => n.toLowerCase().endsWith('.msi'));
  const nsis = listFiles(path.join(bundleDir, 'nsis'), (n) => n.endsWith('-setup.exe'));
  if (msi.length !== 1) throw new Error(`Esperado exatamente 1 .msi em ${bundleDir}/msi; encontrados ${msi.length}.`);
  if (nsis.length !== 1) throw new Error(`Esperado exatamente 1 -setup.exe em ${bundleDir}/nsis; encontrados ${nsis.length}.`);
  return { msi: msi[0], nsis: nsis[0] };
}

export function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

export function formatManifest(entries) {
  // Sempre LF (nunca CRLF): o manifesto é conferido com GNU `sha256sum -c`, que trata o \r
  // como parte do nome do arquivo.
  return [...entries]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((entry) => `${entry.hash}  ${entry.name}\n`)
    .join('');
}

/** Interpreta o manifesto de forma estrita; lança erro se algo fugir do formato do `sha256sum`. */
export function parseManifest(text) {
  if (text.includes('\r')) throw new Error(`${MANIFEST_NAME} contém CR (quebra de linha CRLF); use somente LF.`);
  if (text.length === 0 || !text.endsWith('\n') || text.endsWith('\n\n')) {
    throw new Error(`${MANIFEST_NAME} deve terminar com exatamente uma quebra de linha e não pode ser vazio.`);
  }
  const seen = new Set();
  const entries = [];
  for (const line of text.slice(0, -1).split('\n')) {
    const match = MANIFEST_LINE_RE.exec(line);
    if (!match) throw new Error(`Linha inválida em ${MANIFEST_NAME}: ${JSON.stringify(line)}`);
    const [, hash, name] = match;
    if (name === MANIFEST_NAME) throw new Error(`${MANIFEST_NAME} não pode listar a si mesmo.`);
    if (seen.has(name)) throw new Error(`Nome repetido em ${MANIFEST_NAME}: ${name}`);
    seen.add(name);
    entries.push({ hash, name });
  }
  return entries;
}

/** Recalcula os hashes dos arquivos de `dir` e compara com o manifesto. Devolve a lista de erros. */
export function verifyManifestDir(dir) {
  const errors = [];
  let entries;
  try {
    entries = parseManifest(fs.readFileSync(path.join(dir, MANIFEST_NAME), 'utf8'));
  } catch (error) {
    return [error.message];
  }
  const listed = new Set(entries.map((e) => e.name));
  for (const { hash, name } of entries) {
    const file = path.join(dir, name);
    if (!fs.existsSync(file)) {
      errors.push(`Arquivo listado no manifesto não existe: ${name}`);
    } else if (sha256File(file) !== hash) {
      errors.push(`Hash diferente para ${name}.`);
    }
  }
  for (const name of fs.readdirSync(dir)) {
    if (name !== MANIFEST_NAME && !listed.has(name)) errors.push(`Arquivo fora do manifesto: ${name}`);
  }
  return errors;
}

/**
 * Copia os instaladores reais do Tauri para `outDir` com nomes seguros (sem espaços), calcula o
 * SHA-256 dos arquivos JÁ COPIADOS (os que serão publicados) e grava o manifesto em LF.
 * `version` é a versão completa que precisa aparecer nos nomes dos dois instaladores, impedindo
 * anexar instaladores de outra versão (`wixVersion` é aceito por compatibilidade e não é usado).
 */
export function prepareReleaseAssets({ bundleDir, outDir, version, wixVersion }) {
  if (fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0) {
    throw new Error(`Diretório de saída não está vazio: ${outDir}`);
  }
  const { msi, nsis } = findInstallers(bundleDir);
  const nsisMarker = `_${version}_`;
  // O Tauri 2.11 nomeia NSIS e MSI com a versão completa (`0.1.0-beta.2`); a versão numérica do
  // WiX (`wixVersion`) só vai nos metadados do MSI. Comprovado no build de CI da beta.2.
  const msiMarker = `_${version}_`;
  if (!path.basename(nsis).includes(nsisMarker)) {
    throw new Error(`O instalador NSIS '${path.basename(nsis)}' não contém a versão esperada '${version}'.`);
  }
  if (!path.basename(msi).includes(msiMarker)) {
    throw new Error(`O instalador MSI '${path.basename(msi)}' não contém a versão esperada '${version}'.`);
  }
  fs.mkdirSync(outDir, { recursive: true });
  const entries = [];
  for (const source of [nsis, msi]) {
    const name = sanitizeAssetName(path.basename(source));
    fs.copyFileSync(source, path.join(outDir, name));
    entries.push({ name, hash: sha256File(path.join(outDir, name)) });
  }
  if (new Set(entries.map((e) => e.name)).size !== entries.length) throw new Error('Nomes de instalador duplicados.');
  const manifest = formatManifest(entries);
  fs.writeFileSync(path.join(outDir, MANIFEST_NAME), manifest, 'utf8');
  const errors = verifyManifestDir(outDir);
  if (errors.length > 0) throw new Error(`Auto-verificação do manifesto falhou:\n${errors.join('\n')}`);
  return { entries, manifest };
}
