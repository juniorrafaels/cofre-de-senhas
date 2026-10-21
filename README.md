<div align="center">

<img src="src-tauri/icons/128x128@2x.png" width="128" height="128" alt="Ícone do Cofre de Contas">

# Cofre de Contas

**Gerenciador de senhas open source, local e offline para Windows**
<br>
*Open source, local-first password manager for Windows — your vault never leaves your PC.*

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6)
![Built with Tauri](https://img.shields.io/badge/built%20with-Tauri%202-24C8DB)
![Rust](https://img.shields.io/badge/backend-Rust-B7410E)
![React](https://img.shields.io/badge/frontend-React%20%2B%20TypeScript-3178C6)
![Status](https://img.shields.io/badge/status-beta-orange)

[Funcionalidades](#funcionalidades) ·
[Como instalar](#como-instalar) ·
[Segurança](#limitações-e-alertas-importantes-trade-offs) ·
[Contribuir](#como-contribuir) ·
[English](#english-summary)

</div>

---

O **Cofre de Contas** é um cofre de senhas para desktop que guarda suas contas, credenciais,
notas e dados de autenticação em dois fatores **criptografados no seu próprio computador**.
Não há conta online, servidor, assinatura nem sincronização em nuvem: o arquivo do cofre fica na
sua máquina e só abre com a sua senha mestra.

Ele foi pensado para quem gerencia **muitas contas em muitas plataformas** (redes sociais,
e-mails, projetos de clientes) e quer organizá-las por projeto, plataforma e etiqueta — sem
entregar esses dados a um serviço de terceiros.

> **Estágio do projeto: beta, mantido por uma pessoa.** O código passou por revisões de
> segurança internas (registradas neste repositório), mas **não por uma auditoria independente**.
> Leia [Limitações e Alertas Importantes (Trade-offs)](#limitações-e-alertas-importantes-trade-offs) antes de confiar
> nele as suas senhas mais importantes, e mantenha backups.

## Como instalar

> **Baixou o projeto e só encontrou pastas com código?** Isso é o código-fonte, não o aplicativo:
> não há um `.exe` pronto para abrir nele. Escolha um dos caminhos abaixo.

| Você quer… | Faça isto |
|---|---|
| **Só usar o app** | Baixe o arquivo `…_x64-setup.exe` na página **[Releases](https://github.com/juniorrafaels/cofre-de-senhas/releases)**, instale e abra **Cofre de Contas** pelo menu Iniciar. *(A `v0.1.0-beta.1` foi publicada como ZIP de artefatos do CI; a partir da próxima versão os instaladores e o `SHA256SUMS.txt` ficam soltos na release. Confira o hash antes de instalar — veja [docs/INSTALACAO.md](docs/INSTALACAO.md).)* |
| **Gerar o instalador a partir do código** | Instale Node.js, Rust e o compilador C++ da Microsoft (comandos no guia), extraia o ZIP e dê dois cliques em **`Compilar instalador.bat`**. No final, a pasta com o instalador abre sozinha |
| **Desenvolver / contribuir** | Siga [Compilar a partir do código-fonte](#compilar-a-partir-do-código-fonte-desenvolvedores) |

📘 **Passo a passo completo, primeiros passos (senha mestra, Recovery Key, backup), atualização e
desinstalação:** [docs/INSTALACAO.md](docs/INSTALACAO.md).

## Funcionalidades

**Cofre e criptografia**
- Senha mestra com derivação de chave **Argon2id** e criptografia autenticada **XChaCha20-Poly1305**.
- Senhas, notas, detalhes de 2FA e propriedades marcadas como sensíveis são cifrados individualmente.
- **Recovery Key** opcional (com kit de recuperação para imprimir) para recuperar o acesso.
- **Backup criptografado** (`.vaultbackup`) para exportar e importar o cofre inteiro. Restaurar
  sobre um cofre existente exige a senha mestra atual.
- **Perguntas de segurança** (opcional, com riscos documentados): recuperação offline da senha
  mestra com 3 respostas corretas; você escolhe quantas perguntas cadastrar (ver
  [Limitações e Alertas Importantes](#limitações-e-alertas-importantes-trade-offs)).
- **Segunda senha de recuperação** (opcional): uma senha extra, independente do desbloqueio normal,
  da Recovery Key e das perguntas, que recupera a mesma chave dos dados.
- **Desbloqueio com duas senhas** (opcional, desligado por padrão): o cofre só abre com as duas
  senhas, exigido pelo backend. Perder uma delas impede o desbloqueio normal — leia o aviso antes de
  ativar.
- **Bloqueio progressivo** por tentativas incorretas (opcional, desligado por padrão): espera de 15 s
  até 4 h, guardada no aplicativo e válida entre janelas e reinícios.
- Detalhes, formatos e limites de cada opção: [docs/CREDENCIAIS_E_RECUPERACAO.md](docs/CREDENCIAIS_E_RECUPERACAO.md).

**Proteção durante o uso**
- Bloqueio automático por inatividade (tempo configurável).
- Bloqueio ao minimizar (opcional).
- Bloqueio quando o Windows é bloqueado (Win+L) ou entra em suspensão.
- **Um cofre aberto por vez** em toda a instalação: uma segunda janela/instância não consegue abrir
  outro cofre enquanto o primeiro estiver desbloqueado (lock do sistema operacional, liberado
  automaticamente se o app fechar de forma inesperada).
- Copiar senha sem exibi-la, com limpeza automática da área de transferência. No Windows, segredos
  copiados ficam fora do Histórico (Win+V) e da sincronização em nuvem.
- Limite de tentativas para revelar segredos e para a recuperação por perguntas.

**Organização**
- Contas agrupadas por **projetos** e **plataformas** (19 plataformas pré-cadastradas, editáveis).
- **Data do último login** por conta e selo **"Atualizada"** (válido por 90 dias, renovado só pela
  ação "Marcar como atualizada"); a coluna e o selo podem ser exibidos ou ocultados em Configurações.
- **Indicador de força** da senha ao cadastrar/editar uma conta (mesmo avaliador da senha mestra;
  apenas informa, nunca bloqueia o salvamento).
- **Etiquetas**, favoritos, arquivo e **lixeira** com restauração.
- **Propriedades personalizadas** por conta (ex.: "Chave de API"), sensíveis ou não.
- **Histórico** de alterações por conta e status da conta.
- **Gerador de senhas** configurável.
- Visualização em grade ou lista, colunas configuráveis, escala da interface e tema claro/escuro.
- Interface em **português (Brasil), inglês e espanhol**.

## Por que armazenamento local?

| | Cofre de Contas | Gerenciadores em nuvem (ex.: LastPass, 1Password, Bitwarden) |
|---|---|---|
| Onde ficam os dados | Somente no seu PC | Servidores do provedor (cifrados) + dispositivos |
| Conta online / assinatura | Não | Sim (planos gratuitos variam) |
| Sincronização entre dispositivos | **Não** (use backup manual) | Sim |
| Extensão de navegador / preenchimento automático | **Não** | Sim |
| Aplicativo móvel | **Não** | Sim |
| Compartilhamento em equipe | **Não** | Sim |
| Funciona sem internet | Sim | Parcialmente (cache local) |
| Código aberto | Sim | Bitwarden: sim · LastPass/1Password: não |
| Auditoria de segurança independente | **Ainda não** | Sim, publicadas pelos fornecedores |

O Cofre de Contas é uma **alternativa local** para quem prefere não usar um serviço em nuvem —
não um substituto completo desses produtos, e não tem relação, afiliação ou compatibilidade com
eles (não importa nem exporta cofres do LastPass, 1Password ou Bitwarden). Nomes e marcas
citados pertencem aos respectivos donos.

## Tecnologias

- [Tauri 2](https://tauri.app) (WebView2 no Windows) — app desktop leve
- **Rust** no backend: toda a criptografia, o banco e as regras de segurança ficam aqui
- **React 19 + TypeScript + Vite + Tailwind CSS** na interface
- **SQLite** (via `rusqlite`, embutido) como armazenamento local
- Criptografia: `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize` (RustCrypto)

## Limitações e Alertas Importantes (Trade-offs)

Resumo abaixo. O modelo de segurança completo está em [SECURITY.md](SECURITY.md).

**O que o Cofre protege:** quem obtém **só o arquivo do cofre** (ex.: cópia do disco, backup
vazado) não consegue ler senhas, notas, 2FA nem propriedades sensíveis sem a senha mestra — a
dificuldade depende da força da senha mestra.

**O que o Cofre não protege:**
- Um computador já comprometido (malware, keylogger, acesso administrativo enquanto o cofre está
  aberto). Nenhum gerenciador de senhas local resolve isso.
- **Metadados em texto claro (o que sobrou):** etiquetas, projetos (incluindo as notas de
  projeto), plataformas, propriedades não sensíveis, o texto das perguntas de segurança, status,
  favoritos, datas, vínculos e as imagens/avatares ficam legíveis para quem tiver acesso ao arquivo
  do cofre. **Nome da conta, usuário, e-mail, URLs, categoria e o detalhe do histórico são cifrados**
  (`enc:v2:`, XChaCha20-Poly1305, com AAD de tabela/coluna/linha) — cofres antigos são migrados
  automaticamente no desbloqueio, com um backup pré-migração cifrado (`vault.db.pre-v2.bak`).
  Vestígios do texto puro antigo ainda podem existir em páginas livres do SQLite, no SSD, em cópias
  de sombra e em backups feitos antes da migração. Detalhes em [SECURITY.md](SECURITY.md).
- **Perguntas de segurança são o elo mais fraco** (se você ativá-las): cada resposta pode ser
  testada isoladamente, offline, por quem obtiver o arquivo do cofre ou um backup. É um recurso
  opcional; veja a subseção abaixo e prefira uma **Recovery Key**, que é aleatória.
- Trocar a senha mestra não recriptografa os dados: um backup antigo mais a senha antiga dele
  continuam permitindo abrir os dados. Guarde backups com cuidado e apague os antigos.
- Área de transferência: marcar segredos para ficar fora do Win+V é um pedido ao Windows. Outros
  apps ou malware que leem a área de transferência ainda podem capturar o que foi copiado.
- O bloqueio automático pode ser desativado (valor 0) e o bloqueio ao minimizar vem desligado por
  padrão. O bloqueio no Win+L/suspensão existe só no Windows.
- Excluir uma conta não garante remoção forense dos dados do disco (SQLite WAL, SSD).
- Esquecer a senha mestra **sem** Recovery Key e sem perguntas de segurança válidas = perda definitiva dos dados.
- Sem sincronização: se o disco falhar sem backup, os dados se perdem. Exporte backups.
- Builds não são assinados digitalmente ainda; o Windows SmartScreen pode alertar.
- Não houve auditoria de segurança independente.

**Encontrou uma vulnerabilidade?** Não abra uma issue pública. Siga as instruções em
[SECURITY.md](SECURITY.md).

### Recuperação por perguntas de segurança (opcional)

Recurso **opcional**: você escolhe se quer ativá-lo, e quantas perguntas cadastrar (1 a 20).
Se não cadastrar nenhuma, o desbloqueio normal fica exatamente igual. Para desativar, remova
todas as perguntas em Configurações (exige a senha mestra atual). Funciona **totalmente offline**.

- **Como funciona:** a chave que cifra os dados (DEK) é dividida com *Shamir Secret Sharing*
  (crate `sharks`) com limiar fixo de **3**: uma share por pergunta. Cada share é cifrada com
  XChaCha20-Poly1305 por uma chave derivada de **uma única resposta** (Argon2id, 128 MiB,
  3 iterações, salt aleatório por pergunta; resposta normalizada com `trim` + minúsculas).
  Na recuperação o app sorteia até 5 perguntas e é preciso acertar **pelo menos 3**; a DEK
  reconstruída é conferida contra `dek_check` antes de qualquer desbloqueio. Só então é possível
  definir uma nova senha mestra, e isso só vale em sessão aberta por recuperação.
- **Com menos de 3 perguntas a recuperação não funciona** (o limiar de 3 é parte do formato). O app
  permite salvar 1 ou 2, mas avisa que ainda não bastam. O teto de 20 é o do desenho original
  (o limite técnico do formato é 255 shares).
- **O que fica no `vault.db`:** o **texto** das perguntas (em claro), o salt, os parâmetros do
  Argon2id e a share cifrada. Respostas e DEK nunca são gravadas em claro, nem registradas em logs
  ou mensagens de erro.
- **Limite de tentativas:** 5 falhas bloqueiam novas tentativas por 15 minutos, e cada pedido aceita
  no máximo 5 respostas (sem IDs repetidos). O contador fica no próprio banco: ele limita a
  interface, **não** impede ataque offline contra uma cópia do arquivo.
- **Riscos (factuais):**
  - Quem copiar o `vault.db` (ou um backup) pode testar **cada resposta offline e
    separadamente**, sem limite de tentativas. O custo do ataque é aproximadamente a *soma* dos
    dicionários de cada pergunta, não o produto. Argon2id encarece cada tentativa, mas não
    elimina esse risco.
  - Respostas pessoais costumam ser previsíveis ou fáceis de pesquisar. Use respostas longas e
    únicas (a resposta não precisa ser a verdadeira, mas você precisa guardá-la).
  - Mais perguntas podem dificultar, mas **não** garantem uma quantidade específica de entropia.
  - Uma **Recovery Key** aleatória (120 bits) tem propriedades de segurança diferentes e mais fortes
    do que respostas escolhidas por uma pessoa.
  - A crate `sharks` (RUSTSEC-2024-0398: coeficientes do polinômio sorteados em 1..=255, nunca 0)
    foi **removida**; o app usa `src-tauri/src/shamir.rs`, compatível bit a bit com as shares já
    gravadas. O sorteio com o viés foi mantido de propósito nos cofres existentes (trocá-lo
    quebraria a recuperação de quem já tem perguntas). O ataque do advisory exige o mesmo segredo
    compartilhado centenas de vezes com polinômios independentes; aqui o polinômio é derivado da
    própria DEK e é sempre o mesmo. Com 2 de 3 shares conhecidas, o viés elimina no máximo 2 de 256
    candidatos por byte (cerca de 0,36 bit no total, em 256): irrelevante frente ao elo fraco
    prático, que são as respostas. Detalhes em `docs/CREDENCIAIS_E_RECUPERACAO.md`.
- **Se você perder a senha mestra** e não tiver Recovery Key nem pelo menos 3 respostas corretas
  entre as perguntas sorteadas, os dados são perdidos definitivamente.
- **Cofres já existentes** com perguntas continuam funcionando sem migração, e os backups
  `.vaultbackup` incluem as perguntas (cifradas como no banco).

## Requisitos do sistema

- **Windows 10 (64 bits) ou Windows 11**
- Microsoft Edge **WebView2 Runtime** (já vem no Windows 11 e em Windows 10 atualizados)

O código usa Tauri e pode compilar em macOS/Linux, mas **apenas o Windows é testado**; o bloqueio
ao travar a sessão/suspender é implementado só para Windows.

## Compilar a partir do código-fonte (desenvolvedores)

> Quer só instalar o app? Veja [Como instalar](#como-instalar).

Estas instruções partem de um **Windows recém-instalado**, sem nenhuma ferramenta de
desenvolvimento. Abra o **PowerShell** (não precisa ser como administrador, exceto se o `winget`
pedir) e siga na ordem.

**1. Instale as ferramentas** (uma vez só):

```powershell
# Git
winget install --id Git.Git -e

# Node.js LTS (o projeto exige Node 20.19+ ou 22.12+)
winget install --id OpenJS.NodeJS.LTS -e

# Compilador C++ da Microsoft (exigido pelo Rust no Windows) — workload "Desktop development with C++"
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# Rust (rustup, toolchain MSVC)
winget install --id Rustlang.Rustup -e

# WebView2 — normalmente já instalado; rode só se o app abrir em branco ou reclamar
winget install --id Microsoft.EdgeWebView2Runtime -e
```

> Sem `winget`? Instale manualmente: [Git](https://git-scm.com/download/win),
> [Node.js LTS](https://nodejs.org), [Build Tools for Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
> (marque **Desktop development with C++**), [Rust](https://rustup.rs).

**2. Feche e reabra o PowerShell** (para o PATH novo valer) e confira:

```powershell
git --version
node --version     # v20.19+ ou v22.12+
npm --version
rustc --version
cargo --version
```

Se `cargo` não for encontrado, adicione `%USERPROFILE%\.cargo\bin` ao PATH do usuário ou reinicie
o Windows.

**3. Baixe o código e instale as dependências:**

```powershell
cd $HOME\Documents
git clone https://github.com/juniorrafaels/cofre-de-senhas.git
cd cofre-de-senhas
npm ci
```

**4. Rode em modo desenvolvimento** (a primeira compilação do Rust demora alguns minutos):

```powershell
npm run tauri dev
```

> ⚠️ **O modo dev usa o mesmo cofre do app instalado** (`%APPDATA%\com.rafaelcampos.cofredecontas\`).
> Se você já usa o Cofre de verdade nesta máquina, faça um backup antes de desenvolver, ou use o
> script de cofre de teste descrito em [docs/TESTES_MANUAIS.md](docs/TESTES_MANUAIS.md).

**5. Gere o instalador** (opcional):

```powershell
npm run tauri build
```

Os instaladores ficam em `src-tauri\target\release\bundle\msi\` e `...\bundle\nsis\`.

> Dica: se o projeto estiver numa pasta sincronizada (OneDrive, Dropbox), mova a pasta de build do
> Rust (vários GB) para fora dela antes de compilar:
> `$env:CARGO_TARGET_DIR = "$env:LOCALAPPDATA\cargo-target\cofre-de-contas"`. Os instaladores
> passam a ficar em `<essa pasta>\release\bundle\`. Para tornar isso permanente, veja
> `src-tauri\.cargo\config.toml.example`.
`npm run release` gera apenas um executável portátil `Cofre de Contas.exe` na raiz do projeto.

### Onde ficam os seus dados

| Item | Local |
|---|---|
| Banco do cofre | `%APPDATA%\com.rafaelcampos.cofredecontas\vault.db` |
| Imagens/avatares | `%APPDATA%\com.rafaelcampos.cofredecontas\images\` |
| Backups | Onde você escolher ao exportar (`*.vaultbackup`) |

Desinstalar o app **não** apaga esses arquivos.

## Testes

```powershell
npm test                                            # testes do frontend (Vitest)
npx tsc --noEmit                                    # checagem de tipos
cargo test --manifest-path src-tauri/Cargo.toml --lib   # testes do backend Rust
```

Os testes do Rust usam bancos em memória (ou arquivos temporários) e dados sintéticos; eles não
tocam no seu cofre real. Alguns testes iniciam processos filhos para verificar a exclusividade entre
instâncias (lock do SO); rodam em Windows e usam `File::try_lock` (Rust ≥ 1.89). A suíte do Rust
leva alguns minutos porque várias provas usam o Argon2id real.

Alguns comportamentos só podem ser conferidos com o app aberto (histórico Win+V, restauração de
backup pela interface, recuperação de acesso). O roteiro, com um script que isola o seu cofre real
durante os testes, está em [docs/TESTES_MANUAIS.md](docs/TESTES_MANUAIS.md).

## Como contribuir

Contribuições são bem-vindas: relatos de bugs, traduções, melhorias de acessibilidade e revisões
de segurança. Veja [CONTRIBUTING.md](CONTRIBUTING.md).

- **Nunca** anexe seu `vault.db`, backups ou capturas com dados reais em issues.
- Mudanças em criptografia, recuperação ou backup precisam de testes e de justificativa clara.
- Vulnerabilidades: use o canal privado descrito em [SECURITY.md](SECURITY.md), não issues públicas.

## Licença

Distribuído sob a **[Apache License 2.0](LICENSE)**. Veja também o [NOTICE](NOTICE).

Os logos de plataformas de terceiros incluídos no app (Instagram, X, TikTok, YouTube etc.) são
marcas dos seus titulares, **não** estão cobertos por essa licença e são usados apenas para
identificar as plataformas. O Cofre de Contas não tem afiliação com essas empresas. Detalhes em
[docs/ASSETS.md](docs/ASSETS.md).

---

## English summary

**Cofre de Contas** ("Accounts Vault") is an **open source, local-first password manager for
Windows**, built with Tauri 2, Rust and React. Passwords, notes, 2FA details and sensitive custom
fields are encrypted on your PC with **Argon2id + XChaCha20-Poly1305**; there is no cloud account,
server or sync. It organizes credentials by project, platform and tag, includes a password
generator, encrypted backups, an optional recovery key, and auto-lock on idle, minimize, Windows
session lock and sleep. UI available in Portuguese, English and Spanish.

It is a **local alternative** for people who would rather not use cloud password managers such as
LastPass, 1Password or Bitwarden — it is not affiliated with them, is not compatible with their
vaults, and does not offer browser autofill, mobile apps or sync. **Beta software, not
independently audited.**

**How to install:** download the `…_x64-setup.exe` file from the
[Releases](https://github.com/juniorrafaels/cofre-de-senhas/releases) page (check the SHA-256 in
`SHA256SUMS.txt` before installing; installers are not code-signed, so Windows SmartScreen may warn). Or build it yourself: install Node.js LTS, Rust (rustup) and the Microsoft C++
Build Tools (see the `winget` commands above), extract the source ZIP and double-click
**`Compilar instalador.bat`**. When it finishes, the folder with the installer opens
automatically. Then open **Cofre de Contas** from the Start menu, create a master password and
generate a Recovery Key (*Configurações → Segurança*).

<sub>Keywords: password manager, open source password manager, local password manager, offline
password manager, password manager for Windows, password vault, gerenciador de senhas, cofre de
senhas, gerenciador de senhas offline, alternativa ao LastPass, Tauri, Rust.</sub>
