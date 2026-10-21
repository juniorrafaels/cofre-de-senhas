import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import {
  MANIFEST_NAME,
  checkVersions,
  formatManifest,
  parseManifest,
  parseTag,
  prepareReleaseAssets,
  readCargoPackageVersion,
  sanitizeAssetName,
  verifyManifestDir,
} from '../release-lib.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const tmpDirs = [];
const tmp = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cofre-release-test-'));
  tmpDirs.push(dir);
  return dir;
};
afterEach(() => {
  while (tmpDirs.length) fs.rmSync(tmpDirs.pop(), { recursive: true, force: true });
});

const hasSha256sum = spawnSync('sha256sum', ['--version']).status === 0;

// ---------------------------------------------------------------- versionamento (A3)
describe('parseTag', () => {
  it('aceita estável e beta', () => {
    expect(parseTag('v0.1.0')).toMatchObject({ version: '0.1.0', prerelease: false, wixVersion: null });
    expect(parseTag('v0.1.0-beta.2')).toMatchObject({ version: '0.1.0-beta.2', prerelease: true, wixVersion: '0.1.0.2' });
    expect(parseTag('v1.12.3-beta.65535').wixVersion).toBe('1.12.3.65535');
  });

  it.each([
    'vfoo', 'v0.1', 'v0.1.0-', 'v0.1.0+meta', 'V0.1.0', '0.1.0', 'v0.1.0-rc.1', 'v0.1.0-alpha.1',
    'v0.1.0-beta', 'v0.1.0-beta.0', 'v0.1.0-beta.01', 'v0.1.0-beta.65536', 'v256.0.0', 'v0.256.0', 'v0.0.65536',
    'v01.2.3', 'v0.1.0-beta.1.2', '', undefined,
  ])('recusa %j', (tag) => {
    expect(() => parseTag(tag)).toThrow();
  });

  it('betas diferentes nunca produzem a mesma versão de instalador', () => {
    const versions = ['v0.1.0-beta.1', 'v0.1.0-beta.2', 'v0.1.0'].map(parseTag);
    expect(new Set(versions.map((v) => v.version)).size).toBe(3);
    expect(new Set(versions.map((v) => v.wixVersion)).size).toBe(3); // null, 0.1.0.1, 0.1.0.2
  });
});

describe('readCargoPackageVersion', () => {
  it('lê só a versão de [package], não a de dependências', () => {
    const toml = '[dependencies]\nfoo = { version = "9.9.9" }\nversion = "7.7.7"\n\n[package]\nname = "x"\nversion = "0.1.0-beta.2"\n\n[build-dependencies]\nversion = "1.0.0"\n';
    expect(readCargoPackageVersion(toml)).toBe('0.1.0-beta.2');
  });
});

function fixtureRoot({ pkg = '0.1.0', conf = '0.1.0', cargo = '0.1.0', wix } = {}) {
  const root = tmp();
  fs.mkdirSync(path.join(root, 'src-tauri'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'x', version: pkg }));
  const bundle = wix === undefined ? {} : { windows: { wix: { version: wix } } };
  fs.writeFileSync(path.join(root, 'src-tauri/tauri.conf.json'), JSON.stringify({ version: conf, bundle }));
  fs.writeFileSync(path.join(root, 'src-tauri/Cargo.toml'), `[package]\nname = "x"\nversion = "${cargo}"\n`);
  return root;
}

describe('checkVersions', () => {
  it('estável: versões iguais e sem wix.version', () => {
    expect(checkVersions(fixtureRoot(), parseTag('v0.1.0'))).toEqual([]);
  });

  it('beta: versão completa nos três manifestos e wix.version numérico', () => {
    const root = fixtureRoot({ pkg: '0.1.0-beta.2', conf: '0.1.0-beta.2', cargo: '0.1.0-beta.2', wix: '0.1.0.2' });
    expect(checkVersions(root, parseTag('v0.1.0-beta.2'))).toEqual([]);
  });

  it('beta com manifestos ainda em 0.1.0 é recusado (não deixa betas se confundirem)', () => {
    const errors = checkVersions(fixtureRoot(), parseTag('v0.1.0-beta.2'));
    expect(errors.length).toBeGreaterThanOrEqual(4); // 3 manifestos + wix
    expect(errors.join('\n')).toContain("exige exatamente '0.1.0-beta.2'");
  });

  it('beta sem wix.version, ou com wix.version de outro beta, é recusado', () => {
    const base = { pkg: '0.1.0-beta.2', conf: '0.1.0-beta.2', cargo: '0.1.0-beta.2' };
    expect(checkVersions(fixtureRoot(base), parseTag('v0.1.0-beta.2')).join()).toContain('wix.version');
    expect(checkVersions(fixtureRoot({ ...base, wix: '0.1.0.1' }), parseTag('v0.1.0-beta.2')).join()).toContain('0.1.0.2');
  });

  it('estável com wix.version sobrando é recusado', () => {
    expect(checkVersions(fixtureRoot({ wix: '0.1.0.2' }), parseTag('v0.1.0')).join()).toContain('não deve definir');
  });

  it('um único manifesto divergente já falha', () => {
    for (const field of ['pkg', 'conf', 'cargo']) {
      expect(checkVersions(fixtureRoot({ [field]: '0.2.0' }), parseTag('v0.1.0')).length).toBe(1);
    }
  });

  it('estado atual do repositório: v0.1.0-beta.4 confere; outras tags exigem preparar a versão antes', () => {
    expect(checkVersions(repoRoot, parseTag('v0.1.0-beta.4'))).toEqual([]);
    expect(checkVersions(repoRoot, parseTag('v0.1.0')).length).toBeGreaterThan(0);
    // a beta.3 já foi publicada: o repositório não pode mais casar com ela
    expect(checkVersions(repoRoot, parseTag('v0.1.0-beta.3')).length).toBeGreaterThan(0);
    expect(checkVersions(repoRoot, parseTag('v0.1.0-beta.2')).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------- nomes + manifesto (A1, A2)
function fakeBundle({ nsis = 'Cofre de Contas_0.1.0_x64-setup.exe', msi = 'Cofre de Contas_0.1.0_x64_en-US.msi' } = {}) {
  const dir = tmp();
  fs.mkdirSync(path.join(dir, 'nsis'));
  fs.mkdirSync(path.join(dir, 'msi'));
  fs.writeFileSync(path.join(dir, 'nsis', nsis), 'conteúdo fictício do instalador NSIS');
  fs.writeFileSync(path.join(dir, 'msi', msi), 'conteúdo fictício do instalador MSI');
  return dir;
}

describe('sanitizeAssetName', () => {
  it('troca espaços por hífen e recusa caracteres fora da lista segura', () => {
    expect(sanitizeAssetName('Cofre de Contas_0.1.0_x64-setup.exe')).toBe('Cofre-de-Contas_0.1.0_x64-setup.exe');
    for (const bad of ['a;b.exe', 'a"b.exe', 'ação.exe', 'a/b.exe', 'a\\b.exe', '']) {
      expect(() => sanitizeAssetName(bad)).toThrow();
    }
  });
});

describe('prepareReleaseAssets', () => {
  it('estável: nomes reais do Tauri → nomes seguros, hashes dos arquivos copiados, manifesto em LF', () => {
    const bundleDir = fakeBundle();
    const outDir = path.join(tmp(), 'out');
    const { entries, manifest } = prepareReleaseAssets({ bundleDir, outDir, version: '0.1.0', wixVersion: null });

    const names = entries.map((e) => e.name).sort();
    expect(names).toEqual(['Cofre-de-Contas_0.1.0_x64-setup.exe', 'Cofre-de-Contas_0.1.0_x64_en-US.msi']);
    // O diretório de saída contém exatamente os arquivos do manifesto + o manifesto.
    expect(fs.readdirSync(outDir).sort()).toEqual([...names, MANIFEST_NAME].sort());
    expect(manifest).not.toContain('\r');
    expect(fs.readFileSync(path.join(outDir, MANIFEST_NAME)).includes(0x0d)).toBe(false);
    expect(parseManifest(manifest).map((e) => e.name).sort()).toEqual(names);
    expect(verifyManifestDir(outDir)).toEqual([]);
  });

  it.skipIf(!hasSha256sum)('o manifesto é aceito pelo GNU sha256sum -c (regressão do CRLF)', () => {
    const outDir = path.join(tmp(), 'out');
    prepareReleaseAssets({ bundleDir: fakeBundle(), outDir, version: '0.1.0', wixVersion: null });
    const result = spawnSync('sha256sum', ['-c', MANIFEST_NAME], { cwd: outDir, encoding: 'utf8' });
    expect(result.stdout + result.stderr).toContain('Cofre-de-Contas_0.1.0_x64-setup.exe: OK');
    expect(result.status).toBe(0);
  });

  it('o verificador estrito recusa o manifesto quando vira CRLF (o defeito original)', () => {
    const outDir = path.join(tmp(), 'out');
    prepareReleaseAssets({ bundleDir: fakeBundle(), outDir, version: '0.1.0', wixVersion: null });
    const manifestPath = path.join(outDir, MANIFEST_NAME);
    fs.writeFileSync(manifestPath, fs.readFileSync(manifestPath, 'utf8').replace(/\n/g, '\r\n'));
    // O GNU sha256sum -c rejeita CRLF em algumas versões (ex.: o do Git Bash no Windows) e aceita em
    // outras (coreutils 9.1 no Linux); por isso o contrato testado é o do nosso verificador, que
    // recusa CRLF sempre.
    expect(verifyManifestDir(outDir).join()).toContain('CRLF');
  });

  it('beta: NSIS leva a versão completa e o MSI a numérica; nomes distintos entre betas', () => {
    const run = (n) => {
      const bundleDir = fakeBundle({
        nsis: `Cofre de Contas_0.1.0-beta.${n}_x64-setup.exe`,
        msi: `Cofre de Contas_0.1.0-beta.${n}_x64_en-US.msi`,
      });
      const tag = parseTag(`v0.1.0-beta.${n}`);
      return prepareReleaseAssets({
        bundleDir,
        outDir: path.join(tmp(), 'out'),
        version: tag.version,
        wixVersion: tag.wixVersion,
      }).entries.map((e) => e.name);
    };
    const beta1 = run(1);
    const beta2 = run(2);
    expect(beta1).toContain('Cofre-de-Contas_0.1.0-beta.1_x64-setup.exe');
    expect(beta2).toContain('Cofre-de-Contas_0.1.0-beta.2_x64_en-US.msi');
    expect(beta1.filter((n) => beta2.includes(n))).toEqual([]); // nenhum nome em comum
  });

  it('recusa instaladores de outra versão (ex.: beta.2 com arquivos 0.1.0)', () => {
    const tag = parseTag('v0.1.0-beta.2');
    expect(() =>
      prepareReleaseAssets({ bundleDir: fakeBundle(), outDir: path.join(tmp(), 'out'), version: tag.version, wixVersion: tag.wixVersion }),
    ).toThrow(/não contém a versão esperada/);
  });

  it('recusa quando falta instalador, quando há mais de um, ou quando o diretório de saída não está vazio', () => {
    const noMsi = fakeBundle();
    fs.rmSync(path.join(noMsi, 'msi'), { recursive: true });
    expect(() => prepareReleaseAssets({ bundleDir: noMsi, outDir: path.join(tmp(), 'o'), version: '0.1.0', wixVersion: null })).toThrow(/1 \.msi/);

    const two = fakeBundle();
    fs.writeFileSync(path.join(two, 'nsis', 'Outro_0.1.0_x64-setup.exe'), 'x');
    expect(() => prepareReleaseAssets({ bundleDir: two, outDir: path.join(tmp(), 'o'), version: '0.1.0', wixVersion: null })).toThrow(/1 -setup\.exe/);

    const dirty = tmp();
    fs.writeFileSync(path.join(dirty, 'sobra.txt'), 'x');
    expect(() => prepareReleaseAssets({ bundleDir: fakeBundle(), outDir: dirty, version: '0.1.0', wixVersion: null })).toThrow(/não está vazio/);
  });

  it('detecta troca de arquivo depois do cálculo do hash', () => {
    const outDir = path.join(tmp(), 'out');
    prepareReleaseAssets({ bundleDir: fakeBundle(), outDir, version: '0.1.0', wixVersion: null });
    fs.appendFileSync(path.join(outDir, 'Cofre-de-Contas_0.1.0_x64-setup.exe'), 'adulterado');
    expect(verifyManifestDir(outDir).join()).toContain('Hash diferente');
    fs.writeFileSync(path.join(outDir, 'extra.exe'), 'x');
    expect(verifyManifestDir(outDir).join()).toContain('Arquivo fora do manifesto');
  });
});

describe('parseManifest', () => {
  const hash = 'a'.repeat(64);
  it('aceita o formato do sha256sum e recusa variações', () => {
    expect(parseManifest(`${hash}  a.exe\n`)).toEqual([{ hash, name: 'a.exe' }]);
    expect(() => parseManifest(`${hash}  a.exe\r\n`)).toThrow(/CRLF/);
    expect(() => parseManifest(`${hash}  a.exe`)).toThrow();
    expect(() => parseManifest(`${hash}  a.exe\n\n`)).toThrow();
    expect(() => parseManifest(`${hash} a.exe\n`)).toThrow(); // um espaço só
    expect(() => parseManifest(`${hash.toUpperCase()}  a.exe\n`)).toThrow(); // hash em maiúsculas
    expect(() => parseManifest(`${hash}  a b.exe\n`)).toThrow(); // nome com espaço
    expect(() => parseManifest(`${hash}  a.exe\n${hash}  a.exe\n`)).toThrow(/repetido/);
    expect(() => parseManifest(`${hash}  ${MANIFEST_NAME}\n`)).toThrow();
    expect(() => parseManifest('')).toThrow();
  });

  it('formatManifest ordena por nome e usa só LF', () => {
    const text = formatManifest([{ name: 'b', hash }, { name: 'a', hash }]);
    expect(text).toBe(`${hash}  a\n${hash}  b\n`);
  });
});

// ---------------------------------------------------------------- o workflow usa o que foi testado
describe('release.yml', () => {
  const workflow = fs.readFileSync(path.join(repoRoot, '.github', 'workflows', 'release.yml'), 'utf8');

  it('gera manifesto e nomes pelo script testado, sem Set-Content/Out-File escrevendo o manifesto', () => {
    expect(workflow).toContain('scripts/release-assets.mjs');
    expect(workflow).toContain('scripts/release-check-version.mjs');
    expect(workflow).not.toMatch(/Set-Content|Out-File/); // o Get-FileHash que aparece é só instrução ao usuário nas notas
  });

  it('mantém a conferência com sha256sum -c e a checagem da tag', () => {
    expect(workflow).toContain('sha256sum -c SHA256SUMS.txt');
    expect(workflow).toContain('--verify-tag');
    expect(workflow).toMatch(/--draft/);
  });
});
