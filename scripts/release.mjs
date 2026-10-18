#!/usr/bin/env node
// Compila a build release do Tauri (sem gerar MSI/NSIS) e substitui o executável
// permanente na raiz do projeto: "Cofre de Contas.exe".
//
// Uso: npm run release
//      node scripts/release.mjs --bundle   (também gera os instaladores MSI/NSIS configurados em
//                                           tauri.conf.json — é o modo usado por "Atualizar App.bat")

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcTauriDir = path.join(projectRoot, 'src-tauri');
const finalExeName = 'Cofre de Contas.exe';
const finalExePath = path.join(projectRoot, finalExeName);

// Mesma ordem de precedência do Cargo: variável CARGO_TARGET_DIR > src-tauri/.cargo/config.toml
// (opcional, local, não versionado) > src-tauri/target.
function readTargetDir() {
  if (process.env.CARGO_TARGET_DIR) return path.resolve(srcTauriDir, process.env.CARGO_TARGET_DIR);
  const cargoConfigPath = path.join(srcTauriDir, '.cargo', 'config.toml');
  const defaultTargetDir = path.join(srcTauriDir, 'target');
  if (!fs.existsSync(cargoConfigPath)) return defaultTargetDir;
  const content = fs.readFileSync(cargoConfigPath, 'utf8');
  const match = content.match(/target-dir\s*=\s*"([^"]+)"/);
  if (!match) return defaultTargetDir;
  return path.resolve(srcTauriDir, match[1]);
}

function readBinName() {
  const cargoTomlPath = path.join(srcTauriDir, 'Cargo.toml');
  const content = fs.readFileSync(cargoTomlPath, 'utf8');
  const match = content.match(/^\[package\][\s\S]*?^name\s*=\s*"([^"]+)"/m);
  return match ? match[1] : 'app';
}

function run(commandLine) {
  console.log(`\n> ${commandLine}`);
  execSync(commandLine, { stdio: 'inherit', cwd: projectRoot });
}

const npxCommand = process.platform === 'win32' ? 'npx.cmd' : 'npx';

const withInstallers = process.argv.includes('--bundle');

if (withInstallers) {
  console.log('Compilando build release do Cofre de Contas (com os instaladores do tauri.conf.json)...');
  run(`${npxCommand} tauri build`);
} else {
  console.log('Compilando build release do Cofre de Contas (sem instaladores MSI/NSIS)...');
  run(`${npxCommand} tauri build --no-bundle`);
}

const targetDir = readTargetDir();
const binName = readBinName();
const compiledExePath = path.join(targetDir, 'release', `${binName}.exe`);

if (!fs.existsSync(compiledExePath)) {
  console.error(`\nErro: executável compilado não encontrado em:\n${compiledExePath}`);
  console.error('O build pode ter falhado antes de gerar o binário. O .exe anterior na raiz não foi alterado.');
  process.exit(1);
}

// No Windows, `resource_dir()` do Tauri SEMPRE resolve para a pasta do .exe em execução (dev,
// release "cru" ou instalado) — nunca para o cargo build dir. O Cargo já copia os resources
// declarados em tauri.conf.json para `target/release/resources` ao lado do binário compilado;
// esse .exe permanente vive fora dessa pasta (na raiz do projeto), então precisa da mesma pasta
// `resources` copiada para o lado dele aqui, ou o app roda sem nenhuma imagem padrão de
// plataforma (BUG CRÍTICO já visto em produção: `$APPDATA/images` fica vazio após excluir e
// recriar o cofre porque o provisionamento não acha os arquivos de origem).
const compiledResourcesDir = path.join(targetDir, 'release', 'resources');
const finalResourcesDir = path.join(projectRoot, 'resources');

if (!fs.existsSync(compiledResourcesDir)) {
  console.error(`\nErro: pasta de resources não encontrada em:\n${compiledResourcesDir}`);
  console.error('O build não gerou os resources declarados em tauri.conf.json (ex.: imagens padrão das plataformas).');
  console.error('Publicar o .exe sem isso deixaria o app sem as imagens padrão. Abortando.');
  process.exit(1);
}

const tempPath = path.join(projectRoot, `.${finalExeName}.tmp`);

try {
  fs.copyFileSync(compiledExePath, tempPath);
  // rename é uma substituição atômica no mesmo volume: ou troca o arquivo inteiro,
  // ou falha sem tocar no .exe anterior (nunca deixa a raiz com um arquivo parcial).
  fs.renameSync(tempPath, finalExePath);
} catch (err) {
  try { fs.rmSync(tempPath, { force: true }); } catch { /* melhor esforço */ }

  if (err.code === 'EBUSY' || err.code === 'EPERM') {
    console.error(`\nNão foi possível atualizar "${finalExeName}" porque o arquivo está em uso.`);
    console.error('Feche o aplicativo Cofre de Contas e execute "npm run release" novamente.');
    console.error('O executável anterior continua intacto e funcional.');
    process.exit(1);
  }
  throw err;
}

// ATENÇÃO — não remova esta cópia nem troque por "copiar só o .exe": no Windows o Tauri resolve
// `resource_dir()` sempre em relação à pasta do executável em execução (não ao cargo build dir).
// Se este .exe permanente for publicado/movido sem a pasta `resources/` ao lado dele, o app abre
// normalmente mas o provisionamento das imagens padrão das plataformas falha silenciosamente e
// `$APPDATA/images` fica vazio (bug real já visto em produção — ver git blame desta seção).
// Sincroniza a pasta de resources ao lado do .exe (remove a antiga e recopia inteira — são só
// assets estáticos pequenos, não precisa de um merge incremental).
fs.rmSync(finalResourcesDir, { recursive: true, force: true });
fs.cpSync(compiledResourcesDir, finalResourcesDir, { recursive: true });

console.log(`\n${finalExeName} atualizado com sucesso.`);
console.log(finalExePath);
console.log(`Resources sincronizados em: ${finalResourcesDir}`);
