# Notas de build no Windows

Guia genérico para compilar o Cofre de Contas a partir do código-fonte no Windows. Os comandos
devem ser executados na raiz do repositório, salvo indicação contrária.

## Pré-requisitos

- **Node.js** LTS e **npm**.
- **Rust** estável, instalado via [rustup](https://rustup.rs), com o toolchain MSVC.
- **Microsoft C++ Build Tools** (workload "Desenvolvimento para desktop com C++").
- **WebView2 Runtime**, que já vem no Windows 10/11 atualizados.
- Consulte também os [pré-requisitos oficiais do Tauri 2](https://v2.tauri.app/start/prerequisites/).

Se `cargo` não for encontrado depois de instalar o rustup, confira se `%USERPROFILE%\.cargo\bin`
está no `PATH` do usuário. Alguns instaladores sobrescrevem o `PATH`. Você também pode adicionar
essa pasta só na sessão atual do terminal.

## Passo a passo

```powershell
npm ci                  # instala exatamente as versões do package-lock.json
npm test                # testes do frontend (Vitest)
cd src-tauri
cargo test              # testes do backend Rust (usam bancos temporários/em memória)
cd ..
npm run tauri build     # build de produção: tsc + vite -> cargo build --release -> instaladores
```

Outros scripts úteis:

| Comando | O que faz |
|---|---|
| `npm run tauri dev` | Modo desenvolvimento, com hot reload e DevTools disponível. |
| `npm run build` | Compila **só o frontend** para `dist/`. **Não** gera nem atualiza o executável. |
| `npm run release` | Compila o binário release (sem instaladores) e copia um executável portátil `Cofre de Contas.exe`, mais a pasta `resources/`, para a raiz do projeto. Esses arquivos são ignorados pelo git. |
| `node scripts/release.mjs --bundle` | Igual ao anterior, mas também gera os instaladores MSI/NSIS. |

## Por que o executável pode ficar desatualizado

O frontend (`dist/`) é **embutido no binário** durante a compilação Rust. Rodar só
`npm run build` não altera nenhum `.exe`. Sempre gere o executável de novo (`npm run tauri build` ou
`npm run release`) depois de mudar o código. Se usar a cópia portátil, abra a cópia recém-gerada.

## Onde ficam os artefatos

O diretório de build do Cargo (`<target-dir>`) é `src-tauri/target/` por padrão. Ele pode ser
outro se você definir `CARGO_TARGET_DIR` ou `target-dir` num `src-tauri/.cargo/config.toml` local
(esse arquivo não é versionado).

| Artefato | Caminho |
|---|---|
| Binário de desenvolvimento | `<target-dir>/debug/tauri-app.exe` |
| Binário de produção | `<target-dir>/release/tauri-app.exe` |
| Instalador NSIS | `<target-dir>/release/bundle/nsis/Cofre de Contas_<versão>_x64-setup.exe` |
| Instalador MSI | `<target-dir>/release/bundle/msi/Cofre de Contas_<versão>_x64_en-US.msi` |

Para conferir qual binário você está executando, compare o SHA-256 dele com o do binário de
produção recém-gerado:

```powershell
Get-FileHash ".\Cofre de Contas.exe"
```

## Dados do cofre durante o desenvolvimento

O app de desenvolvimento, o executável portátil e as instalações usam **o mesmo diretório de
dados** (`%APPDATA%\<identifier>\`, onde `<identifier>` é o `identifier` de
`src-tauri/tauri.conf.json`), porque o identificador é o mesmo. Para testar sem tocar num cofre
real:

1. Feche todas as instâncias do app.
2. Renomeie temporariamente `%APPDATA%\<identifier>` para `<identifier>.BACKUP`.
3. Faça os testes com dados sintéticos e depois apague a pasta de teste.
4. Renomeie `<identifier>.BACKUP` de volta para o nome original.

Os builds não são bit a bit reprodutíveis, então dois builds seguidos geram hashes diferentes.

## Atualizar uma instalação existente

Gerar um instalador novo **não** atualiza uma cópia já instalada. Execute o instalador NSIS ou MSI
recém-gerado. Se ele recusar por ser "a mesma versão", aumente `version` em
`src-tauri/tauri.conf.json` (e em `package.json`/`src-tauri/Cargo.toml`, para manter consistência)
antes de compilar de novo. O cofre em `%APPDATA%` é preservado.

## Quando o build falhar

| Sintoma | O que fazer |
|---|---|
| `cargo` não encontrado | Instale o Rust via rustup e corrija o `PATH` (ver acima). |
| `npm ci` falha | `package.json` e `package-lock.json` estão fora de sincronia. Rode `npm install` e revise o diff do lockfile. |
| Teste falhando | Corrija o código ou o teste. Não altere testes de segurança só para eles passarem. |
| "Arquivo em uso" ao gerar o `.exe` | Feche o app aberto e rode de novo. |
| Build inconsistente (último recurso) | Em `src-tauri/`, rode `cargo clean --release`. O próximo build fica mais lento. |
