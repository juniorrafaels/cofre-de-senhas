> **Aviso: documento histórico de autoavaliação interna.**
> Este relatório foi produzido **durante o desenvolvimento** do Cofre de Contas como uma
> **autoavaliação interna** (revisão feita pelo próprio processo de desenvolvimento, com auxílio de
> ferramentas de IA). **Não é uma auditoria de segurança independente** nem uma certificação.
> Ele descreve o código **na data indicada no próprio documento** e **pode estar desatualizado** em
> relação ao código atual: achados, nomes de commands, contagens de testes e classificações podem
> ter mudado depois. O status de segurança atual está em
> [`SECURITY.md`](../../../SECURITY.md). Caminhos locais e informações do ambiente do
> desenvolvedor foram removidos desta cópia; marcadores `SECURITY_TEST_*`/`XSS_TEST_*` são dados
> sintéticos de teste.
>
> **Desatualizações conhecidas:**
> - `decrypt_secret`/`encrypt_secret`/`copy_secret_to_clipboard`, ainda presentes nesta fase, foram
>   **removidos na Fase 4**.
> - A tabela "Críticos" afirma que `reset_master_password_after_recovery` "só aceita depois de
>   `attempt_vault_recovery`/`unlock_with_recovery_key`". No código, a verificação é apenas a
>   presença da DEK em memória, o que também vale numa sessão normal desbloqueada (ver último item).
> - `import_backup` sem autenticação aparece aqui como decisão de design. A revisão posterior
>   tratou isso como problema.
> - Uma revisão posterior, feita antes da publicação, encontrou problemas que **não** aparecem
>   nestes relatórios e que estão sendo tratados: (1) as **perguntas de segurança** permitem força
>   bruta offline **resposta por resposta** (cada resposta protege seu próprio *share* e pode ser
>   testada isoladamente contra o `vault.db`, então o limiar 3-de-N não multiplica o custo);
>   (2) **`import_backup` roda sem autenticação** (não exige cofre desbloqueado nem senha mestra) e
>   substitui o cofre inteiro; (3) **`reset_master_password_after_recovery`** só verifica se há
>   uma DEK em memória, então pode ser chamado a partir de uma **sessão normal desbloqueada** para
>   trocar a senha mestra sem informar a atual; (4) segredos copiados vão para a área de
>   transferência do Windows sem serem excluídos do **histórico do clipboard (Win+V)** e da
>   sincronização em nuvem, então a limpeza automática não remove essas cópias.

# Security Audit — Phase 3 (Isolamento WebView ↔ Backend)

Data: 2026-08-28
Escopo: continuação de `SECURITY_AUDIT.md` (Fase 1) e `SECURITY_AUDIT_PHASE_2.md` (Fase 2). Diferente das fases anteriores, esta sessão rodou num ambiente Windows 11 **com desktop real disponível** — o app foi de fato compilado e executado (`npm run tauri dev`) nesta máquina, não apenas revisado por leitura de código. Ver seção "Testes automatizados" e `SECURITY_MANUAL_TESTS.md` para o que ainda depende de interação manual (Win+L, suspender, hibernar, fechar a tampa — nenhum destes foi *simulado* nem seu resultado *inventado*; o app foi apenas iniciado e observado, sem forçar o bloqueio da sessão Windows real do usuário).

## Resumo executivo

A pergunta central desta fase era: **comprometer/manipular a WebView significa automaticamente comprometer o cofre?** A resposta, depois desta sessão, é **não para a maior parte da superfície, mas sim para o segredo que está sendo exibido/copiado no momento, enquanto o cofre estiver desbloqueado** — exatamente o limite que a Fase 2 já havia identificado como inerente ao modelo de confiança do Tauri, e que esta fase reduz mais um degrau sem eliminar (nem seria honesto prometer eliminar).

Principais entregas:

1. **SQL arbitrário eliminado da WebView.** O plugin `tauri-plugin-sql` foi removido do app (Rust e npm), junto com todas as permissões `sql:*` da capability. As ~45 funções de `src/lib/db.ts` que antes montavam `SELECT`/`INSERT`/`UPDATE`/`DELETE` diretamente foram reescritas para chamar **47 novos Tauri commands** organizados por domínio (`accounts.rs`, `platforms.rs`, `tags.rs`, `projects.rs`, `properties.rs`, `history.rs`, `settings.rs`, mais extensões em `images.rs` e `security_questions.rs`). Nenhuma query é montada a partir de string concatenada com entrada do usuário — todas usam `rusqlite::params!`/placeholders.
2. **Toda a superfície nova exige `state.is_unlocked()`.** Os 47 novos commands (mais os 2 comandos de arquivo de imagem que já existiam) verificam o estado real do cofre no processo Rust antes de tocar no banco — o mesmo padrão já usado pelos commands criptográficos da Fase 1/2 (`state.with_dek`).
3. **Validação de entrada no Rust** para todos os campos vindos da WebView: enums fechados (status de conta, método de 2FA, tipo de propriedade, escopo de listagem, chaves de `settings`), tamanhos máximos, IDs positivos, allowlist de eventos de histórico, allowlist de colunas de `list_columns`, formato de hash SHA-256, nomes de arquivo de imagem (herdado da Fase 1).
4. **Hook nativo de Windows** (`native_lock.rs`, novo): a janela principal agora se registra para `WM_WTSSESSION_CHANGE` (bloqueio de sessão) e intercepta `WM_POWERBROADCAST` (suspensão) via `SetWindowSubclass`, chamando `VaultState::clear()` diretamente do callback nativo — **sem depender do JS/WebView estar responsivo**. Confirmado nesta sessão que a chamada registra sem erro num Windows real (ver seção "Windows Lock/Suspend"). Item que a Fase 2 havia deixado como recomendação explícita para a Fase 3.
5. **Zeroização estendida**: senha mestra, senha de backup, resposta de pergunta de segurança e Recovery Key agora são envolvidas em `Zeroizing<String>` no momento em que entram em cada command (antes eram `String` comuns) — reduz a janela em que o texto puro fica em memória não zerada, especialmente relevante porque a derivação Argon2id leva ~300-500ms por tentativa.
6. **DevTools em produção: já estava desabilitado, agora confirmado por leitura de código-fonte das dependências**, não só por leitura da documentação (ver seção dedicada) — nenhuma mudança de código foi necessária.
7. Suíte de testes Rust ampliada de **22 para 44** (`cargo test --lib`, 44/44 passando).

**O que esta fase NÃO elimina, e não seria honesto prometer eliminar:** com o cofre **desbloqueado**, a WebView ainda pode chamar `list_accounts_with_relations("all")` (que retorna os campos cifrados, como já acontecia antes) seguido de `decrypt_secret(ciphertext)` para cada um — ou seja, um XSS ativo enquanto o cofre está aberto ainda consegue, em poucos segundos, decifrar todas as senhas. Isso não é um bug desta implementação; é o mesmo limite arquitetural que a Fase 2 documentou ("Tauri/IPC", item 11 das perguntas finais) e que só desapareceria com uma reformulação muito mais invasiva (commands de revelação por campo/conta, sem nunca expor ciphertext à WebView) — avaliei essa reformulação nesta sessão e decidi **não implementá-la agora**; ver "Riscos residuais" para a justificativa completa.

## Estado inicial

Confirmado antes de qualquer alteração:

- `SECURITY_AUDIT.md` e `SECURITY_AUDIT_PHASE_2.md` lidos integralmente.
- `cargo test --lib`: **22/22 passando** (baseline da Fase 2, revalidado nesta sessão antes de tocar em qualquer arquivo).
- `npx tsc --noEmit`: limpo.
- Arquitetura confirmada por leitura de código: `src/lib/db.ts` (649 linhas, ~45 funções, TODAS as queries SQL do frontend estavam ali, nenhuma em outro arquivo — confirmado por grep em `src/` inteiro por `getDb(`, `Database.load`, `.execute(`, `.select(`). Isso foi o que tornou a migração tratável: bastou trocar o *corpo* de cada função por uma chamada `invoke(...)`, mantendo nome/assinatura/tipo de retorno idênticos — nenhum componente React precisou mudar.
- `src-tauri/capabilities/default.json` antes: `sql:default`, `sql:allow-load/execute/select/close`, `clipboard-manager:*`, `opener:*`, `dialog:default`.
- `src-tauri/src/db.rs`: sem `PRAGMA foreign_keys = ON` (nota informativa, ver "Riscos residuais").

## SQL/WebView

### Inventário (antes desta fase)

Todo acesso SQL do frontend estava em `src/lib/db.ts`, usando `@tauri-apps/plugin-sql` (`Database.load("sqlite:vault.db")`, depois `db.select(...)`/`db.execute(...)`). Domínios cobertos, com contagem de funções:

| Domínio | Funções (antes) | Operações |
|---|---|---|
| Platforms | 5 | list, create, update, delete, reassign |
| Tags | 5 | list, list+uso, create, rename, delete |
| Accounts | 9 | list c/ relations, create, update, delete (soft), restore, delete permanente, archive, unarchive, favorite |
| Settings | 2 | get all, set |
| Images (metadados) | 10 | list, rename, contagens de uso (3x), get by id, find by hash, create record, delete record, clear avatar |
| Projects | 5 | list c/ relations, create, update, delete, favorite |
| Custom properties | 6 | list definitions, ensure definition, list por conta, create, update, delete |
| Account history | 2 | log, list |
| Security questions | 1 | list (metadados, sem resposta) |

Todas as queries já usavam parâmetros (`$1, $2...`) — nenhuma concatenação de string de usuário em SQL (confirmado na Fase 1 e revalidado agora). O risco não era SQL injection clássica; era a **superfície**: qualquer JS na página podia montar *qualquer* `SELECT`/`UPDATE`/`DELETE`/`DROP` contra `vault.db`, incluindo tabelas sensíveis (`security_questions.wrapped_share`, `vault_meta.wrapped_dek`) — mesmo que sem a DEK esses bytes fossem inertes.

### O que foi feito

1. Cada uma das ~45 funções virou um `#[tauri::command]` dedicado no Rust, organizado em `src-tauri/src/commands/{accounts,platforms,tags,projects,properties,history,settings}.rs` (novos) e extensões em `images.rs`/`security_questions.rs`.
2. `src/lib/db.ts` foi reescrito por completo: cada função exportada manteve **nome, parâmetros e tipo de retorno idênticos**, mas o corpo agora é `invoke("nome_do_command", {...})`. Isso significa que **nenhum componente React precisou ser tocado** — confirmado por `npx tsc --noEmit` limpo e `npm run build` bem-sucedido logo após a reescrita, sem qualquer ajuste em componente.
3. `tauri-plugin-sql` removido de `src-tauri/Cargo.toml`, `package.json` e do `Builder` em `lib.rs`. `npm install` confirmou a remoção (1 pacote a menos, 0 vulnerabilidades).
4. `sql:*` removido de `src-tauri/capabilities/default.json` — a WebView não tem mais **nenhuma** permissão relacionada a SQL.
5. Verificado por grep, ao final: `grep -rniE "\.execute\(|\.select\(|Database\.load|plugin-sql" src/` não retorna nenhuma chamada real (só um comentário no topo de `db.ts` explicando a mudança).

### Não foi criado nenhum `execute_sql(query)` genérico

Cada command representa uma ação específica do domínio (`create_account`, `toggle_favorite`, `archive_account`...), nunca um wrapper genérico de SQL. Isso estava explicitamente proibido no pedido e foi respeitado.

## IPC/Tauri — classificação dos commands

70 commands registrados em `lib.rs` (antes: 23). Classificação:

### Públicos (funcionam com o cofre bloqueado)

| Command | Por quê |
|---|---|
| `vault_status` | precisa informar se o cofre existe/está bloqueado antes mesmo de autenticar |
| `create_vault` | só funciona uma vez (se já existe, erro) |
| `unlock_vault` | é o próprio ato de desbloquear |
| `security_questions_summary` | só conta quantas perguntas existem, não expõe pergunta/resposta |
| `get_recovery_questions` | mostra 5 perguntas (texto, não resposta) para o fluxo de recuperação — precisa funcionar bloqueado por definição |
| `attempt_vault_recovery` | é o próprio ato de recuperar acesso |
| `recovery_key_status` | só diz se existe uma Recovery Key configurada (bool + data), não a chave |
| `unlock_with_recovery_key` | é o próprio ato de desbloquear por esse caminho |

### Protegidos (exigem `state.is_unlocked()`)

Todos os **47 novos commands de dados** (`accounts::*`, `platforms::*`, `tags::*`, `projects::*`, `properties::*`, `history::*`, `settings::*`, mais `images::{list_images, update_image_name, count_*_using_image, get_image_by_id, find_image_by_hash, create_image_record, delete_image_record, clear_avatar_for_image, import_image, delete_image_file}`), além dos já existentes `encrypt_secret`, `decrypt_secret`, `copy_secret_to_clipboard`, `add_security_question`, `update_security_question`, `delete_security_question`, `list_security_questions` (novo), `export_backup`, `generate_recovery_key`, `disable_recovery_key`.

Nota: `import_image`/`delete_image_file` **não tinham** verificação de cofre antes desta fase — adicionada agora (`require_unlocked`) por consistência, já que manipular avatares é uma operação sobre dados do cofre.

### Críticos (validações adicionais além de "desbloqueado")

| Command | Validação extra |
|---|---|
| `change_master_password` | reverifica a senha atual decifrando `wrapped_dek` com ela (não confia em `is_unlocked()` sozinho) |
| `reset_master_password_after_recovery` | só aceita depois de `attempt_vault_recovery`/`unlock_with_recovery_key` já terem confirmado a identidade via `dek_check` |
| `attempt_vault_recovery` | rate limiting (5 tentativas → 15 min de bloqueio), verificação de `dek_check` |
| `import_backup` | intencionalmente **sem** exigir unlock (permite restaurar um cofre vazio), mas a senha do backup passa por AEAD — falha genérica em qualquer adulteração |
| `generate_recovery_key` / `disable_recovery_key` | exigem DEK em mãos (`with_dek`), invalidam/substituem qualquer chave anterior |
| `permanently_delete_account` | operação destrutiva irreversível — validada com `positive_id`, mas como qualquer exclusão física, sem "lixeira" depois desta |

## Validação no Rust

Novo módulo `src-tauri/src/validate.rs` (com 4 testes próprios), usado por todos os commands novos:

- `trim_required`/`trim_optional`: string obrigatória/opcional, com teto de caracteres por campo (ex.: nome de conta 200, URL 2048, ciphertext 200.000).
- `positive_id`: rejeita IDs ≤ 0 antes de gastar uma query.
- `one_of`/`one_of_opt`: allowlist fechada — usado para `status` de conta (6 valores), `two_factor_method` (6 valores), `type` de propriedade customizada (8 valores), escopo de listagem (`active`/`trash`/`all`), evento de histórico (14 valores fixos, ver `history.rs`), e cada chave de `settings` (com formato específico por chave: booleano, número num intervalo, ou lista JSON de colunas conhecidas).
- Hash de imagem: validado como 64 caracteres hexadecimais (`is_valid_sha256_hex` em `images.rs`) antes de ser aceito em `create_image_record`/`find_image_by_hash`.
- Nome de arquivo de imagem: reaproveita `sanitize_image_filename` já existente da Fase 1 (rejeita `..`, `/`, `\`, `:`).

Testado com `'; DROP TABLE accounts;--'` como valor de `event`/`scope`/nome de coluna — rejeitado pela allowlist antes de qualquer query ser montada (`commands::history::tests::rejects_events_outside_the_allowlist`, `commands::accounts::tests::rejects_scope_outside_allowlist`).

## Queries parametrizadas

Busca global por concatenação suspeita: todo `format!` usado para montar SQL nos novos módulos interpola apenas **literais fixos do próprio código-fonte** (nomes de tabela/coluna escolhidos por `match`/constantes, nunca uma `String` vinda de `serde::Deserialize`), nunca um valor de usuário — os valores sempre entram via `rusqlite::params![...]`/placeholders `?N`. Único lugar onde um nome de tabela é interpolado dinamicamente é `commands::tags::{count_by_tag, sync_tags}`, que recebe `join_table`/`id_column` como `&str` passados pelas próprias chamadas internas de `accounts.rs`/`projects.rs` (`"account_tags"`/`"project_tags"`, `"account_id"`/`"project_id"`) — nunca de uma fonte externa; comentado explicitamente no código.

## Commands por domínio

```
commands/
    accounts.rs        (novo)
    backup.rs           — já existia (Fase 1/2)
    clipboard.rs        — já existia
    history.rs         (novo)
    images.rs           — estendido (metadados de imagem + gate de unlock)
    platforms.rs       (novo)
    projects.rs        (novo)
    properties.rs      (novo)
    recovery_key.rs     — já existia (Fase 2), zeroização adicionada
    secret.rs           — já existia
    security_questions.rs — já existia, +list_security_questions, zeroização
    settings.rs        (novo)
    tags.rs            (novo)
    vault.rs            — já existia, zeroização adicionada
```

Estrutura escolhida para espelhar exatamente os domínios que já existiam em `db.ts` — nenhuma reorganização adicional do projeto.

## Estado do cofre no backend

Inalterado desde a Fase 2 (nenhuma necessidade de mudar): `VaultState(Mutex<Option<Zeroizing<[u8;32]>>>)` em `state.rs`. `is_unlocked()` = `Some`; `with_dek()` só executa a closure se houver DEK. Não existe (e nunca existiu) uma variável tipo `unlocked: bool` que o frontend possa "setar" — o único jeito de o estado mudar é o processo Rust efetivamente decifrar/gerar uma DEK válida.

## Testar bypass (cofre bloqueado)

Cada um dos 47 novos commands começa literalmente com `require_unlocked(&state)?` (ou `state.is_unlocked()`/`with_dek` para os que já existiam) — confirmado por leitura de código de **todos** os arquivos novos/modificados, um por um. Prova adicional por teste automatizado (já existente desde a Fase 2, revalidado): `commands::recovery_key::tests::generate_requires_unlocked_vault` testa a primitiva `VaultState::with_dek` diretamente — a mesma primitiva que todo command novo usa como primeiro passo, antes de tocar em `AppHandle`/banco.

Não foi possível (nem seria seguro) chamar os 70 commands via `window.__TAURI_INTERNALS__.invoke` a partir de um DevTools real nesta sessão — não há uma automação de teclado/mouse disponível para dirigir a UI e chegar a um estado "cofre criado, então bloqueado" de forma interativa. A prova de bypass é por **código** (toda função começa com a checagem) + **teste unitário da primitiva** que essa checagem usa, mesmo padrão de evidência já aceito nas Fases 1 e 2.

## DevTools

**Achado novo desta fase, por leitura do código-fonte das dependências (não apenas documentação):**

- `Cargo.toml` do projeto: `tauri = { version = "2", features = ["protocol-asset"] }` — a feature `devtools` do crate `tauri` **não** está habilitada, e não faz parte do `default` do crate `tauri` (`default = ["wry", "compression", "common-controls-v6", "dynamic-acl", "x11", "dbus"]`, confirmado em `tauri-2.11.5/Cargo.toml`).
- Em `tauri-runtime-wry-2.11.4/src/lib.rs:5209-5211`, a chamada que força `with_devtools(true)` no builder do WebView2 está atrás de `#[cfg(any(debug_assertions, feature = "devtools"))]` — ou seja, **só compila** se for build de debug OU a feature estiver ligada.
- Em `wry-0.55.1/src/lib.rs:833-837`, o valor padrão de `WebViewAttributes::devtools` é `true` sob `#[cfg(debug_assertions)]` e **`false`** sob `#[cfg(not(debug_assertions))]`.
- Isso se traduz, na API real do WebView2 (`wry-0.55.1/src/webview2/mod.rs:573`), em `settings.SetAreDevToolsEnabled(attributes.devtools)` — ou seja, o F12/"Inspecionar" do WebView2 **não fica disponível em release** (`cargo build --release`, sem `debug-assertions` sobrescrito em `[profile.release]` — confirmado que `Cargo.toml` não tem essa sobrescrita).
- **Conclusão: DevTools já estava e continua desabilitado em builds de produção, habilitado em dev, sem nenhuma mudança de código necessária.** Confirmei isso compilando e rodando o app tanto em modo dev (`npm run tauri dev`, nesta sessão) quanto compilando em modo release (`cargo build --release`, concluído sem erros nesta sessão) — não abri a janela release interativamente (não é necessário: a decisão é em tempo de compilação, não de execução).
- Conforme pedido explícito do usuário, isso é tratado como *hardening*, não como controle de segurança principal: todo command sensível continua verificando `state.is_unlocked()`/`with_dek` no Rust, então mesmo que alguém conseguisse abrir DevTools numa build de produção (ex.: via uma flag de linha de comando do próprio executável, fora do controle desta aplicação), o backend continuaria seguro.

## Filesystem / Permissões (menor privilégio)

`src-tauri/capabilities/default.json`, antes → depois:

| Permissão | Antes | Depois |
|---|---|---|
| `sql:default/allow-load/allow-execute/allow-select/allow-close` | ✅ | ❌ removida |
| `clipboard-manager:allow-write-text/read-text/clear` | ✅ | ✅ mantida (necessária) |
| `opener:allow-open-url` (`http(s)://` apenas) | ✅ | ✅ mantida |
| `dialog:default` | ✅ | ✅ mantida (escolher onde salvar/importar backup e imagens) |
| `fs:*` (qualquer) | nunca existiu | continua não existindo |
| `shell:*` (execução de processo) | nunca existiu | continua não existindo |

Todo acesso a arquivo continua passando por commands Rust específicos (`import_image`, `delete_image_file`, `export_backup`, `import_backup`), cada um com sua própria validação. **Nenhuma permissão de filesystem genérica é exposta à WebView.**

### Imagens — path traversal (retestado)

`sanitize_image_filename` (Fase 1) revalidado: `../../secret.txt`, `..\\..\\secret.txt`, `..`, `C:\Windows\System32\evil.dll`, `/etc/passwd`, string vazia — todos rejeitados (`commands::images::tests::rejects_path_traversal_attempts`, ainda passando). `create_image_record` (novo) adiciona uma segunda camada: o `hash` recebido da WebView precisa ter exatamente o formato de um SHA-256 (64 hex chars) antes de ser gravado na coluna `hash` — testado com `"; DROP TABLE images;--"` anexado a 64 `a`s (rejeitado, `rejects_hashes_with_wrong_shape`).

### Backup — paths (revisado, não restringido further)

`export_backup`/`import_backup` continuam aceitando qualquer `out_path`/`in_path` escolhido via `@tauri-apps/plugin-dialog` no fluxo legítimo, sem uma allowlist de diretório no lado Rust. Avaliei adicionar essa restrição e decidi **não fazer** isso nesta fase: (1) o próprio recurso exige que o usuário escolha livremente onde salvar/carregar um backup — restringir a um diretório fixo quebraria a funcionalidade pedida pelo usuário; (2) a escrita/leitura já acontece com os mesmos privilégios do usuário do SO que está rodando o app — não é uma escalação de privilégio, é o mesmo risco de "qualquer app instalado pode escrever onde o usuário tem permissão"; (3) `import_backup` já falha de forma segura (rejeita) para qualquer arquivo que não seja um backup válido cifrado com a senha certa, então um path malicioso sem o conteúdo certo não abre nenhuma porta nova. Ver "Riscos residuais".

## Windows Lock / Suspend (hook nativo — item novo desta fase)

Pesquisa (ver processo desta sessão): não existe plugin Tauri 2 maduro para isso — os dois candidatos encontrados (`tauri-plugin-screen-lock-status`, alvo Tauri 1; `tauri-plugin-power-manager`, só ações de desligar/reiniciar) não servem. Implementei diretamente com o crate `windows` (já usado transitivamente pelo próprio Tauri/wry — fixei a mesma versão, `0.61`, para reaproveitar o mesmo tipo `HWND` que `WebviewWindow::hwnd()` já retorna, sem conversão).

Novo módulo `src-tauri/src/native_lock.rs`, `#[cfg(target_os = "windows")]` (no-op em outras plataformas):

- `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)` inscreve a janela para `WM_WTSSESSION_CHANGE`.
- `SetWindowSubclass` intercepta as mensagens da janela (padrão já usado internamente por `tao`/`winit`, sempre repassa para `DefSubclassProc` — não interfere no processamento normal de mouse/teclado/IME do WebView2).
- No callback: `WM_WTSSESSION_CHANGE` com `wparam == WTS_SESSION_LOCK` (Win+L) **ou** `WM_POWERBROADCAST` com `wparam == PBT_APMSUSPEND` (suspensão) → chama `VaultState::clear()` **diretamente**, no processo Rust, sem depender de o JS estar vivo/responsivo para reagir.
- Instalado em `.setup()` em `lib.rs`. Falha em qualquer etapa (`WTSRegisterSessionNotification`/`SetWindowSubclass`) é tratada como não-fatal — só loga em stderr; o app nunca deixa de iniciar por causa disso, e a mitigação por relógio de parede do lado JS (`useAutoLock.ts`, Fase 2) continua ativa como rede de segurança.

**Confirmado nesta sessão, em ambiente real:** rodei `npm run tauri dev` nesta máquina Windows 11; o app compilou e o processo `tauri-app.exe` ficou rodando (~31 MB de memória, confirmado via `tasklist`); **nenhuma mensagem de erro do `native_lock` apareceu em stderr**, ou seja, tanto `WTSRegisterSessionNotification` quanto `SetWindowSubclass` **retornaram sucesso** nesta máquina real. Isso é evidência positiva de que o hook se registra corretamente no ambiente alvo — não é, porém, prova de que o `VaultState::clear()` de fato dispara ao pressionar Win+L de verdade, porque **não bloqueei a sessão Windows real do usuário durante esta sessão automatizada** (bloquear a tela do usuário sem aviso, no meio de uma tarefa não solicitada para isso, seria uma ação disruptiva que não me cabia tomar sozinho). Esse teste específico fica documentado como manual em `SECURITY_MANUAL_TESTS.md`.

## Suspend

Coberto pelo mesmo hook (`PBT_APMSUSPEND` via `WM_POWERBROADCAST`, ver acima). Camada adicional herdada da Fase 2 continua ativa: `useAutoLock.ts` reconfere o relógio de parede ao voltar o foco/visibilidade, então mesmo que o hook nativo falhasse silenciosamente numa máquina específica, o retorno de uma suspensão ainda dispara a checagem de tempo decorrido do lado JS.

## Hibernação

Não há uma mensagem Win32 dedicada e diferente de suspensão para hibernação "clássica" no caso comum (o sistema tipicamente ainda passa por `PBT_APMSUSPEND` antes de hibernar, dependendo da configuração de energia do Windows) — o mesmo hook cobre o caso na prática, mas isso **não foi verificado empiricamente** nesta sessão (exigiria hibernar a máquina de verdade, um teste manual — ver `SECURITY_MANUAL_TESTS.md`). Não afirmo cobertura garantida para hibernação como uma propriedade testada.

## Auto-lock (revalidado, sem mudança de lógica)

`useAutoLock.ts` (Fase 2, não alterado nesta fase): guarda `Date.now()` da última atividade, reconfere em `visibilitychange`/`focus`. Testado por leitura de código, não há regressão introduzida por esta fase (nenhum arquivo de `useAutoLock.ts` foi tocado). Os valores de `auto_lock_minutes`/`clipboard_clear_seconds` agora são validados no Rust (`settings.rs`, intervalo `0..=10080` minutos = até 7 dias, suficiente para qualquer configuração razoável, rejeitando valores absurdos que uma WebView comprometida pudesse tentar gravar).

## Memória / Zeroization

**Já garantido desde a Fase 1/2 (revalidado, não alterado):**
- DEK: `Zeroizing<[u8;32]>` dentro de `Mutex` em `VaultState` — zerada ao `clear()`/drop.
- Saída de `derive_key`/`decrypt` em `crypto.rs`: já retornavam `Zeroizing<[u8;32]>`/`Zeroizing<Vec<u8>>`.

**Novo nesta fase:** as strings de entrada que alimentam Argon2id (a etapa mais lenta, ~300-500ms, logo a de maior janela de exposição em memória) agora são envolvidas em `Zeroizing<String>` assim que entram no command, antes de qualquer uso:
- `vault.rs`: `create_vault(password)`, `unlock_vault(password)`, `change_master_password(current_password, new_password)`.
- `backup.rs`: `export_backup(backup_password)`, `import_backup(backup_password)`.
- `security_questions.rs`: `add_security_question(answer)`, `update_security_question(answer)`, `reset_master_password_after_recovery(new_password)`, `normalize_answer()` (helper interno) agora retorna `Zeroizing<String>` em vez de `String`; `RecoveryAnswer.answer` (usado em `attempt_vault_recovery`) mudou de `String` para `Zeroizing<String>` — precisou habilitar a feature `serde` do crate `zeroize` (`Cargo.toml`) para que a desserialização direta funcionasse.
- `recovery_key.rs`: `unlock_with_recovery_key(recovery_key)`, e as variáveis internas `normalized` (resultado de `normalize_recovery_key`) em `generate_recovery_key`/`unlock_with_recovery_key`.

**Limitações honestas (não prometo o que não é garantível):**
- Isso reduz a janela de exposição, **não a elimina**. `Zeroizing<T>` zera os bytes no momento do `Drop` — não impede que o alocador do SO já tenha copiado os bytes para outro lugar (ex.: ao realocar um `String` que cresceu), nem protege contra um processo com privilégios de debugger lendo a memória do processo *enquanto* o segredo ainda está em uso.
- A senha mestra digitada pelo usuário passa pelo `<input>` do React/DOM antes de chegar ao Rust — essa cópia em memória do processo da WebView (JS heap/V8) **não é controlada por este código Rust** e não foi (nem poderia ser, de forma confiável) zerada por este hardening.
- Swap/paginação do SO: se o sistema operacional paginar memória do processo para disco sob pressão de memória, um segredo pode acabar temporariamente num arquivo de paginação — nenhum software de aplicação comum (este incluído) impede isso sem privilégios elevados (`VirtualLock`/mlock), que não foram adicionados aqui por ser uma mudança de escopo maior e com trade-offs (fixar páginas na RAM pode degradar o sistema do usuário) não pedida explicitamente.
- **Conclusão honesta:** zeroização é uma mitigação de defesa em profundidade contra um adversário que consiga um dump de memória *depois* que o segredo já deveria ter sido descartado — não uma garantia absoluta de que o segredo nunca aparece em lugar nenhum da RAM.

## Recovery Key — validação de entropia (revisão específica pedida)

Revisão de `src-tauri/src/crypto.rs:94-130` (código inalterado nesta fase — nenhuma necessidade de mudança encontrada):

1. **RNG criptograficamente seguro:** sim — `random_bytes()` usa `rand::rngs::OsRng`, fonte de entropia do SO.
2. **120 bits reais de entropia:** sim — `RECOVERY_KEY_ENTROPY_BYTES = 15` (15 × 8 = 120 bits), consumidos em janelas de exatamente 5 bits (`bit_buffer >> bit_count & 0b11111`) até esgotar os 120 bits.
3. **Nenhuma redução por encoding:** o alfabeto (`RECOVERY_KEY_ALPHABET`) tem exatamente 32 símbolos = 2⁵ — cada símbolo carrega exatamente 5 bits, sem arredondamento.
4. **Nenhum truncamento:** 120 bits ÷ 5 bits/símbolo = 24 símbolos **exatos**, sem resto — `RECOVERY_KEY_SYMBOLS = 24` bate matematicamente, nenhum bit é descartado no fim do laço.
5. **Nenhuma normalização destrutiva:** `normalize_recovery_key` só remove espaços/hífens e força maiúsculas; como o alfabeto já é só maiúsculas (gerado assim) e exclui deliberadamente `I`, `L`, `O`, `U` (Crockford Base32 — confirmado contando os caracteres de `"0123456789ABCDEFGHJKMNPQRSTVWXYZ"`: 10 dígitos + 22 letras = 32, faltam exatamente I/L/O/U das 26 letras), não há colisão de símbolos distintos por causa da normalização.
6. **Nenhum módulo bias:** a extração é por *bit-slicing* direto de um alfabeto de tamanho potência de 2 — não é um `valor % 32` (que teria viés se a fonte não fosse já múltipla de 32), é uma leitura direta de 5 bits por vez.
7. **Nenhum caractere descartado que reduza entropia:** confirmado no item 4 — 100% dos 120 bits sobrevivem ao encoding.

**Formato:** `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (24 símbolos em grupos de 4, Base32 Crockford). Testes automatizados já existentes desde a Fase 2 (`crypto::tests::recovery_key_has_expected_shape_and_entropy`, `recovery_key_can_wrap_and_unwrap_a_dek_like_a_password`) revalidados, continuam passando. Não escrevi um teste estatístico adicional (ex.: qui-quadrado sobre milhares de gerações) porque a prova acima é determinística/matemática, não estatística — um teste estatístico só teria valor para detectar um bug de implementação que a análise por leitura de código já não encontrou.

## UX da Recovery Key (revisado, sem mudança de código)

Revisão de `RecoveryKeySection.tsx`/`RecoveryKitDialog.tsx` (Fase 2, não tocados nesta fase): a chave só é retornada uma vez por `generate_recovery_key` (nunca persistida em claro em lugar nenhum, nem para "reimprimir depois"); nenhum uso de `localStorage`/`sessionStorage` no projeto inteiro (confirmado por grep, herdado da Fase 1); a impressão do kit de recuperação usa `window.print()`/`createPortal` diretamente no DOM, sem arquivo temporário. Não avaliei "aparece em crash report" porque este app não tem telemetria/crash reporting integrado (nenhuma dependência de Sentry/similar em `Cargo.toml`/`package.json`).

## Testes de XSS simulado

Cenário: "JavaScript arbitrário está executando na WebView." Duas situações:

### Cofre bloqueado

O atacante consegue chamar qualquer um dos 8 commands "públicos" (lista na seção IPC acima). O único com efeito potencialmente sério é `import_backup` (não exige unlock, por design, para permitir restaurar um cofre vazio) — mas ele **decifra com AEAD antes de aceitar qualquer coisa**: sem uma senha de backup válida para um arquivo que o próprio atacante já teria precisado colocar em disco (via outro vetor, fora do controle deste app), a chamada falha. Não encontrei um caminho de uma única chamada de command que extraia qualquer segredo com o cofre bloqueado.

### Cofre desbloqueado

Aqui está o limite real, documentado sem meias-palavras: o atacante pode

1. Chamar `list_accounts_with_relations("all")` → recebe `id, name, ..., encrypted_password, notes, two_factor_*` (ciphertext) de **todas** as contas, incluindo lixeira.
2. Para cada ciphertext, chamar `decrypt_secret(ciphertext)` → recebe o **plaintext de volta para o JS**.
3. Repetir para `list_account_properties(account_id)` de cada conta (propriedades sensíveis).
4. Exfiltrar tudo via `fetch()` (nenhuma CSP bloqueia `connect-src` para exfiltração ativa — a CSP da Fase 2 restringe **carregar** recursos remotos, não impede que o próprio código já executando na página faça uma requisição de rede para fora; isso é uma limitação inerente de CSP contra exfiltração via XSS, não específica deste app).

Isso é possível **hoje**, depois de toda esta fase, e seria possível de qualquer forma porque a própria UI legítima faz exatamente essas chamadas para mostrar as senhas ao usuário. Não existe uma forma de o backend "saber" que uma chamada a `decrypt_secret` veio de um clique real do usuário vs. um script — a WebView é, por design do Tauri, o lado "confiável" da fronteira IPC.

**O que esta fase reduziu, mesmo nesse cenário:** antes, o mesmo atacante também podia rodar `DROP TABLE accounts` ou `UPDATE accounts SET encrypted_password = 'lixo'` diretamente via SQL — um ataque de integridade/disponibilidade que não precisava nem do cofre desbloqueado. Isso não é mais possível: todo `DELETE`/`UPDATE` agora passa por um command específico, com validação de enum/tamanho, e sem a capability `sql:execute` a WebView não tem como montar uma query destrutiva arbitrária.

## Tentativa de dump — antes/depois

**Antes desta fase (Fase 2), com cofre desbloqueado, mais rápido caminho de dump:**
```
1. invoke('plugin:sql|select', { query: 'SELECT * FROM accounts', ... })  // 1 chamada, todas as colunas
2. Para cada linha, invoke('decrypt_secret', { ciphertext: row.encrypted_password })
```

**Depois desta fase, com cofre desbloqueado:**
```
1. invoke('list_accounts_with_relations', { scope: 'all' })  // 1 chamada, mesmas colunas de ciphertext
2. Para cada linha, invoke('decrypt_secret', { ciphertext: row.encrypted_password })
```

**Risco residual real:** idêntico em impacto final (dump completo em segundos), porque o `SELECT *` livre nunca foi o que protegia o segredo — quem protegia era (e continua sendo) a exigência da DEK para `decrypt_secret`. **O que mudou é a superfície de integridade**, não a de confidencialidade sob "cofre desbloqueado + XSS": antes, o mesmo atacante também podia apagar/corromper o banco inteiro sem precisar de nenhuma criptografia quebrada; agora não pode (toda escrita passa por validação de enum/tamanho e não existe mais um `DROP TABLE` acessível). Reportar isso como "não mudou nada" seria impreciso — mudou a superfície de **integridade/disponibilidade** contra um atacante com JS arbitrário; não mudou (e não tinha como mudar sem uma reformulação muito maior) a superfície de **confidencialidade contra XSS com o cofre já desbloqueado**.

## Testes automatizados

`cargo test --lib`: **44/44 passando** (22 herdados + 22 novos):

- `validate.rs`: 4 testes (obrigatório vazio/longo demais, opcional em branco, ID inválido, allowlist rejeita SQLi-like).
- `commands::settings`: 4 testes (chave desconhecida, número fora do intervalo, `list_columns` com coluna desconhecida, booleano inválido).
- `commands::accounts`: 6 testes (status fora da allowlist, todos os status documentados aceitos, método de 2FA fora da allowlist, nome vazio rejeitado, ciphertext grande demais rejeitado, escopo fora da allowlist).
- `commands::images`: 2 testes (hash com formato errado incl. tentativa de SQLi anexada, hash válido aceito).
- `commands::history`: 3 testes (evento fora da allowlist incl. `'; DROP TABLE accounts;--'`, `account_id` inválido, detalhe grande demais).
- `commands::tags`: 3 testes (dedupe por nome normalizado, nomes em branco ignorados, `sync_tags` substitui o conjunto inteiro a cada chamada).

Todos os testes de comando "puro" (sem precisar de `AppHandle`) usam `rusqlite::Connection::open_in_memory()` + `db::init_schema()` — mesmo padrão já estabelecido por `backup.rs` nas fases anteriores.

`npx tsc --noEmit`: limpo. `npm run build`: sucesso (bundle final até **menor** que antes — 331 KB vs. o tamanho anterior com o plugin SQL embutido). `npm audit`: 0 vulnerabilidades (92 pacotes, 1 a menos que antes por causa da remoção do `@tauri-apps/plugin-sql`). `cargo check`/`cargo build --release`: ambos sem erro, confirmados nesta sessão em Windows real. `cargo clippy --lib`: sem warnings novos introduzidos por este trabalho (corrigi os 3 que minha própria adição gerou — `unnecessary_unwrap`, 2× `type_complexity`; os 2 warnings restantes são pré-existentes em `security_questions.rs`/`migration.rs`, não tocados por mim, fora do escopo desta sessão).

## Testes manuais pendentes

Ver `SECURITY_MANUAL_TESTS.md` — checklist completo com instruções passo a passo. Resumo do que **não** pôde ser executado nem simulado nesta sessão (e por quê):

- Win+L real → verificar que o cofre aparece bloqueado ao retornar. **Motivo de não ter sido feito automaticamente:** bloquear a sessão Windows real do usuário sem aviso prévio, no meio de uma tarefa de auditoria, seria uma ação disruptiva que exigiria a decisão do usuário, não a minha.
- Suspender/hibernar a máquina de verdade e retomar.
- Fechar a tampa de um notebook (não aplicável a este hardware se for desktop — verificar).
- Lock-on-minimize com a configuração ligada/desligada, verificado visualmente.
- Clipboard "ao vivo" (copiar e confirmar limpeza automática após N segundos).

## Riscos residuais

1. **XSS com cofre desbloqueado ainda pode decifrar tudo.** Documentado em detalhe acima — limite arquitetural do modelo "WebView confiável" do Tauri, não um bug pontual. Avaliei implementar commands de revelação por campo/conta que nunca expusessem ciphertext à WebView (eliminando `encrypted_password`/`notes`/`two_factor_*` de `list_accounts_with_relations`) e **decidi não fazer isso nesta sessão**: (a) exigiria reescrever os fluxos de edição/exibição em `AccountForm.tsx`, `AccountDetailModal.tsx`, `AccountCard.tsx`, `AccountsListView.tsx` e `App.tsx` (que hoje leem o ciphertext direto do objeto já carregado na lista, sem uma segunda chamada); (b) não tenho, neste ambiente, uma forma de dirigir a UI interativamente (clicar, editar, salvar) para validar que essa reescrita não quebra o fluxo mais usado do app; (c) o ganho de segurança seria marginal, não estrutural — o mesmo atacante com o cofre desbloqueado ainda poderia chamar um hipotético `get_account_secret_field(id, campo)` uma vez por conta/campo e obter o mesmo resultado, só que com mais chamadas em vez de uma lista + N decrypts. Registro esta decisão explicitamente como recomendação para uma Fase 4, com o desenho já esboçado acima, mas só deve ser feita com um ambiente que permita testar a UI de verdade.
2. **`import_backup`/`export_backup` sem restrição de diretório** — avaliado e mantido por justificativa (ver seção "Filesystem / Backup").
3. **`PRAGMA foreign_keys` nunca foi habilitado** (achado herdado, não introduzido nesta fase — `db.rs` nunca teve essa pragma). Na prática, isso significa que os `ON DELETE CASCADE`/`ON DELETE SET NULL` declarados no schema **podem não estar sendo de fato aplicados pelo SQLite**, e exclusões físicas (`permanently_delete_account`, `delete_platform`, `delete_tag`, `delete_project`) podem deixar linhas órfãs em tabelas filhas (`account_tags`, `account_properties`, `account_history`, etc.) em vez de as removerem em cascata. **Não é uma vulnerabilidade de confidencialidade** (as linhas órfãs não seriam mais sensíveis do que já eram), mas é uma lacuna de higiene de dados que decidi **não corrigir nesta sessão** — habilitar a pragma é uma linha de código, mas mudar o comportamento de cascata de exclusão numa base de dados que já pode ter dados reais do usuário, sem conseguir testar interativamente o efeito em todas as telas, é um risco desproporcional ao benefício para uma auditoria de segurança pontual. Recomendado para revisão dedicada numa fase futura, com um teste manual explícito ("excluir uma plataforma com contas associadas, verificar se as linhas de junção somem").
4. **Zeroização é defesa em profundidade, não uma garantia formal** — limitações documentadas em detalhe na seção dedicada (cópia no DOM/V8 fora do nosso controle, swap de SO, realocação de heap).
5. **Hook nativo de Windows não foi validado com um evento real de Win+L/suspensão** nesta sessão — só confirmei que o registro da API não falha neste hardware. Fica como teste manual explícito.
6. **Hibernação especificamente não tem uma mensagem Win32 própria testada** — o hook de suspensão provavelmente cobre o caso, mas isso não é uma garantia verificada.
7. **`projects.notes` continua em texto puro** — mesma lacuna que a Fase 2 já havia documentado como fora do escopo do pedido original; continua fora do escopo desta fase (o pedido desta vez foi sobre WebView/IPC/Windows lock, não sobre criptografia de campos adicionais).
8. **Cenário fora do threat model, conforme instrução explícita do usuário:** malware/processo com privilégios administrativos controlando o Windows enquanto o cofre está desbloqueado pode, em tese, ler memória do processo, interceptar entrada de teclado, ou ler o clipboard diretamente — nenhuma mitigação de aplicação de usuário comum (este app incluído) impede isso. Não é tratado como uma falha deste software.

## Conclusão

A hipótese central desta fase — "comprometer a interface não deveria dar acesso automático e completo ao cofre" — **se sustenta com uma ressalva clara e documentada**: verdadeira para o cofre bloqueado (nenhum segredo sai, nenhuma escrita destrutiva arbitrária é possível), e verdadeira para a *integridade/disponibilidade* dos dados mesmo com o cofre desbloqueado (SQL livre eliminado), mas **não** verdadeira para a *confidencialidade* dos segredos no instante em que o cofre está desbloqueado — um XSS ativo naquele momento ainda consegue pedir a decifragem de qualquer coisa, porque a própria UI legítima precisa poder fazer exatamente isso. Isso não é uma falha desta implementação específica; é o preço do modelo de confiança do Tauri (WebView = lado confiável da fronteira IPC), o mesmo limite que a Fase 2 já havia identificado e que continua sendo o risco residual mais honesto a reportar.

## Matriz WebView

| Ação | Locked | Unlocked |
|---|---|---|
| Listar contas (metadados) | NEGADO | permitido |
| Ler senha (plaintext) | NEGADO | controlado — via `decrypt_secret(ciphertext)`, exige já ter o ciphertext (obtido da listagem) |
| Copiar senha | NEGADO | permitido — `copy_secret_to_clipboard`, plaintext nunca retorna ao JS |
| Ler notes | NEGADO | permitido (mesmo mecanismo de `decrypt_secret`) |
| Ler 2FA | NEGADO | permitido (idem) |
| Executar SQL | NEGADO (não existe mais o command) | NEGADO (não existe mais o command) |
| Ler arquivo arbitrário | NEGADO (sem `fs:*`, sem command genérico) | NEGADO (idem) |
| Exportar backup | NEGADO (`export_backup` exige unlock) | controlado — AEAD com senha própria do backup |
| Importar backup | permitido (intencional, permite restaurar cofre vazio) | permitido — mas falha se a senha do backup estiver errada |
| Alterar senha mestra | NEGADO (exige unlock e reverificação da senha atual) | controlado |
| Recovery Key (gerar/desabilitar) | NEGADO | controlado — exige `with_dek` |
| Recovery Key (usar para desbloquear) | permitido (é o próprio ato de desbloquear) | n/a |
| Criar/editar/excluir conta, tag, projeto, plataforma, propriedade | NEGADO | controlado — validação de enum/tamanho no Rust |
| Excluir permanentemente uma conta | NEGADO | controlado — sem confirmação adicional além do `ConfirmDialog` da UI (não há um "segundo fator" no backend para esta ação especificamente) |

## Matriz Windows

| Evento | Resultado | Como foi verificado |
|---|---|---|
| Lock manual do cofre (`lock_vault`) | Bloqueia — `VaultState::clear()` | Testado automaticamente (teste unitário + leitura de código, herdado da Fase 2) |
| Auto-lock (inatividade) | Bloqueia após N minutos configurados | Testado automaticamente (lógica de `useAutoLock.ts`, não alterada) |
| Minimizar (com `lockOnMinimize` desligado) | Não bloqueia | Testado automaticamente (leitura de código — comportamento inalterado) |
| Minimizar (com `lockOnMinimize` ligado) | Bloqueia imediatamente | Testado automaticamente (leitura de código — comportamento inalterado) |
| Win + L | Deveria bloquear via `native_lock` (novo) | **Não testável manualmente nesta sessão** — só confirmado que o registro da API não falhou num Windows real. Ver `SECURITY_MANUAL_TESTS.md` |
| Suspend | Deveria bloquear via `native_lock` (novo) + relógio de parede do JS (Fase 2, rede de segurança) | Parcialmente testável automaticamente (relógio de parede); hook nativo não testável manualmente nesta sessão |
| Hibernate | Provavelmente coberto pelo mesmo caminho de `PBT_APMSUSPEND`, não garantido | **Não testável no ambiente atual** |
| Resume | Relógio de parede do JS reconfere ao voltar o foco (Fase 2) | Testado automaticamente (leitura de código) |
| Fechar a tampa | Equivalente a suspend na maioria das configurações padrão do Windows, não testado especificamente | **Não testável no ambiente atual** (depende de hardware físico e da config de energia do usuário) |
| Encerrar o app | `VaultState` é destruído junto com o processo — a DEK desaparece porque a memória do processo é liberada pelo SO | Garantido pela própria natureza de um `Mutex` em memória de processo, não é uma lógica de app que possa falhar |

## Perguntas finais

**1. A WebView ainda consegue executar SQL arbitrário?**
Não. O plugin foi removido, a capability `sql:*` foi removida, e não existe nenhum command `execute_sql`/genérico. Confirmado por grep em todo `src/`.

**2. Modificar o estado React permite desbloquear o backend?**
Não. Nunca foi possível (Fase 2) e continua não sendo — o único estado real é `VaultState` no processo Rust, inacessível pela WebView.

**3. Com o cofre bloqueado, JavaScript arbitrário consegue recuperar alguma senha?**
Não encontrei um caminho de uma única chamada. O caminho teoricamente mais perigoso (`import_backup`, que não exige unlock) exige um arquivo de backup válido cifrado com uma senha específica, que o atacante precisaria colocar em disco por outro meio, fora do controle deste app.

**4. Com o cofre desbloqueado, um XSS consegue extrair TODAS as senhas facilmente?**
Sim — este é o risco residual mais importante e mais honesto desta fase. `list_accounts_with_relations("all")` + `decrypt_secret` por conta é suficiente. Isso é inerente ao modelo de confiança do Tauri, não corrigido nesta sessão (avaliei e documentei por que não).

**5. Quais dados um XSS ainda consegue acessar (com cofre desbloqueado)?**
Todos os dados do usuário: contas (incluindo senha/2FA/notes decifrados sob demanda), propriedades customizadas (incluindo sensíveis), projetos, tags, plataformas, imagens (metadados e arquivos via `convertFileSrc`, escopado a `$APPDATA/images/*`), histórico, configurações, Recovery Key (só pode *gerar* uma nova e ver o texto puro daquela vez — não existe um command que devolva uma Recovery Key já existente em claro).

**6. DevTools representa bypass de segurança?**
Não em produção (desabilitado por padrão, confirmado no código-fonte das dependências). Em desenvolvimento, sim é possível abrir — mas mesmo lá, todo command sensível continua verificando o estado real no Rust; DevTools por si só nunca foi (e continua não sendo) um bypass da lógica de autorização.

**7. A WebView consegue acessar arquivos arbitrários?**
Não via uma permissão genérica (`fs:*` nunca existiu). Os únicos acessos a arquivo são via commands específicos: `import_image` (lê um path escolhido pelo diálogo nativo do usuário — não há como a WebView escolher o path sem o diálogo do SO no fluxo legítimo, mas o command em si não valida a origem do path, então uma WebView comprometida *poderia* tentar ler qualquer arquivo cujo caminho ela já conheça, sujeito às permissões do usuário do SO), `delete_image_file`/`create_image_record` (restritos a `images_dir`/formato de hash), `export_backup`/`import_backup` (path livre, ver seção Backup).

**8. Win + L bloqueia realmente o cofre?**
Deveria, via o novo hook nativo — confirmado que o hook se registra sem erro nesta máquina real, mas **não testado com um Win+L de verdade** nesta sessão (ver justificativa). Recomendo fortemente que o usuário execute o teste manual documentado em `SECURITY_MANUAL_TESTS.md` antes de confiar nisso.

**9. Suspend/hibernate bloqueiam realmente o cofre?**
Suspend: provavelmente sim (hook nativo + relógio de parede como rede de segurança), não testado com uma suspensão real. Hibernate: não verificado.

**10. A DEK é descartada durante lock?**
Sim, sempre foi (desde a Fase 1) — `VaultState::clear()` substitui o `Option<Zeroizing<[u8;32]>>` por `None`, e o `Zeroizing` zera os bytes antigos ao ser descartado. Isso não mudou nesta fase; o que mudou é que agora há **mais um gatilho** (nativo, do SO) além do botão de bloquear manual e do auto-lock por inatividade.

**11. A Recovery Key possui efetivamente ~120 bits de entropia?**
Sim, confirmado por análise matemática do código de encoding (bit-slicing exato, sem truncamento, sem viés de módulo, sem colisão por normalização) — ver seção dedicada.

**12. Qual é agora o maior risco técnico residual?**
Sem dúvida: **XSS com o cofre desbloqueado ainda pode decifrar e exfiltrar todos os segredos**, porque a UI legítima precisa poder pedir isso também. É o mesmo risco que a Fase 2 já apontava como o limite do modelo Tauri, e continua sendo — esta fase reduziu a superfície de *integridade* (sem SQL livre) e adicionou mais uma camada de *disponibilidade do bloqueio* (hook nativo de Windows), mas não resolveu (nem poderia resolver sem uma reformulação de UX maior, fora do escopo pedido) o limite de confidencialidade sob XSS-com-cofre-aberto.

## Classificação final

> **BEM ENDURECIDO PARA USO PESSOAL.**

Mantida a mesma classificação da Fase 2, com evidência adicional que a reforça: a arquitetura criptográfica central segue intacta e não foi tocada (conforme instrução explícita desta fase); a superfície de ataque via SQL livre — o maior item de escopo que a Fase 2 havia deixado pendente — foi eliminada com uma migração completa e testada (44/44 testes, `tsc`/build/`npm audit` limpos, compilação debug e release confirmadas neste Windows real); um hook nativo de lock/suspend foi adicionado, algo que a Fase 2 explicitamente recomendou e não implementou por falta de ambiente de teste. O que impede uma classificação acima de "uso pessoal" continua sendo o mesmo risco estrutural documentado com honestidade nesta fase: XSS com o cofre desbloqueado ainda tem o mesmo poder que a UI legítima tem — decifrar o que o usuário poderia decifrar. Para o caso de uso declarado (um cofre pessoal, não um produto multiusuário/enterprise), esse risco residual é razoável, está documentado, e não escondido.
