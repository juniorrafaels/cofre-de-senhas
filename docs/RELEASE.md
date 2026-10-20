# Como publicar uma versão (para o mantenedor)

A publicação é feita pelo workflow [`release.yml`](../.github/workflows/release.yml), disparado por
uma **tag**. Ele não assina os instaladores (não há certificado de assinatura de código): ele
compila numa máquina limpa do GitHub, publica os arquivos, o `SHA256SUMS.txt` e uma attestation de
proveniência.

## 1. Escolha o tipo de versão

| Tag | Tipo | O que o workflow faz |
|---|---|---|
| `vX.Y.Z-beta.N` (N ≥ 1) | beta | publica uma **pré-release** depois de conferir os arquivos |
| `vX.Y.Z` | estável | cria um **rascunho** conferido; você revisa e clica em *Publish release* |

Qualquer outro formato (`rc`, `alpha`, `v1.0`, `v1.0.0+build`) é recusado. Limites do Windows
Installer: `X` e `Y` até 255, `Z` e `N` até 65535.

## 2. Prepare as versões (PR para a `main`)

A versão da tag precisa bater **exatamente** com os manifestos; o job *Validar tag* falha caso
contrário.

**Beta `vX.Y.Z-beta.N`:**

- `package.json` → `"version": "X.Y.Z-beta.N"`
- `src-tauri/tauri.conf.json` → `"version": "X.Y.Z-beta.N"` **e**
  `bundle.windows.wix.version` = `"X.Y.Z.N"`:
  ```json
  "bundle": { "windows": { "wix": { "version": "X.Y.Z.N" } } }
  ```
- `src-tauri/Cargo.toml` → `version = "X.Y.Z-beta.N"`
- Atualize os arquivos de lock (`package-lock.json` e `src-tauri/Cargo.lock`, por exemplo com
  `npm install --package-lock-only` e `cargo check` em `src-tauri`) e faça merge na `main`.

**Estável `vX.Y.Z`:** os três manifestos em `X.Y.Z` e **sem** `bundle.windows.wix.version`.

Para conferir antes de criar a tag: `node scripts/release-check-version.mjs vX.Y.Z-beta.N`.

### Por que betas usam versão completa + versão numérica no MSI

Decisão técnica (código do `tauri-bundler` 2.11.4, lido para esta decisão):

- **NSIS (`-setup.exe`)** aceita a versão semver completa: o nome do arquivo e o app mostram
  `0.1.0-beta.2`.
- **MSI (WiX)** só aceita versão numérica `major.minor.patch[.build]`. O Tauri só consegue
  converter um pré-release **numérico** (`0.1.0-2` → `0.1.0.2`); com `-beta.2` o build **falha**.
  Por isso o beta define `bundle.windows.wix.version` = `X.Y.Z.N`.
- **Identidade e upgrade do MSI não mudam:** o `UpgradeCode` é derivado do nome do produto (não é
  alterado aqui) e o template do Tauri usa `MajorUpgrade` com `AllowSameVersionUpgrades="yes"`.
  O Windows Installer ignora o 4º campo da versão ao comparar, então: instalar um beta mais novo
  sobre um anterior funciona (conta como "mesma versão", permitida), e a transição de beta para a
  estável `X.Y.Z` também. **Limitação:** instalar um beta *mais antigo* sobre um mais novo não é
  bloqueado pelo MSI.
- **NSIS e upgrade:** a regra de reinstalação do instalador NSIS do Tauri **não foi verificada**
  aqui.
- Resultado: dois betas nunca produzem arquivos com o mesmo nome nem a mesma versão de MSI, e a
  tag, os nomes dos arquivos e as notas da release dizem a mesma versão. Os identificadores do
  produto (`identifier`, `UpgradeCode`) **não foram alterados**.

## 3. Proteja as tags no GitHub (uma vez)

O workflow confere que a tag ainda aponta para o commit compilado e que ele está na `main`, mas
isso **não substitui** a proteção do repositório. Configure em *Settings → Rules → Rulesets* uma
regra para as tags `v*` que **bloqueie exclusão e atualização** (e restrinja quem pode criá-las).
Sem isso, quem tem escrita pode apagar e recriar uma tag.

## 4. Crie a tag (a partir da `main`)

```powershell
git switch main; git pull
git tag vX.Y.Z-beta.N
git push origin vX.Y.Z-beta.N
```

## 5. O que o workflow garante (e o que ainda é manual)

1. Valida formato da tag, versões e que o commit está na `main`.
2. Roda `npm audit`, `cargo audit`, `tsc`, Vitest, `cargo test`, clippy e o build Tauri.
3. Gera os instaladores, troca espaços dos nomes por `-` (`Cofre-de-Contas_<versão>_x64-setup.exe`,
   `Cofre-de-Contas_<versão>_x64_en-US.msi`), calcula o SHA-256 **dos arquivos que serão
   publicados** e grava o `SHA256SUMS.txt` em LF (`scripts/release-assets.mjs`).
4. Confere de novo os hashes, que o diretório tem só os arquivos do manifesto e que a tag ainda
   aponta para o commit compilado; gera a attestation.
5. Cria a release como **rascunho**, baixa de volta pela API os arquivos que o GitHub guardou e
   compara byte a byte com o que foi enviado e com o manifesto.
6. Beta: publica a pré-release. Estável: **fica como rascunho** para você revisar.

Se algo falhar depois do passo 5, a rascunho criada permanece para inspeção: **apague-a** antes de
tentar de novo (o workflow não sobrescreve releases).

Os arquivos de build locais (`npm run installer`) continuam com os nomes originais do Tauri (com
espaços); a padronização de nomes acontece só na publicação.
