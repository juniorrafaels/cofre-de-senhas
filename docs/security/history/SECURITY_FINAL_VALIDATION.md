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
> - A seção "Bugs encontrados" diz que **nenhum bug de segurança novo** foi encontrado. A revisão
>   posterior **encontrou problemas** que esta validação não detectou (ver último item).
> - A classificação "BEM ENDURECIDO PARA USO PESSOAL" é a opinião daquela data e não substitui o
>   status atual.
> - A seção sobre o cofre já existente na máquina de desenvolvimento foi resumida. Detalhes do
>   ambiente local (caminhos, datas e contagens de registros) foram removidos.
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

# Security Final Validation

Data: 2026-08-29
Escopo: última etapa da auditoria de segurança do Cofre — validação como **produto real**, não
apenas leitura de código. Continuação de `SECURITY_AUDIT.md` (Fase 1), `SECURITY_AUDIT_PHASE_2.md`
(Fase 2), `SECURITY_AUDIT_PHASE_3.md` (Fase 3), `SECURITY_AUDIT_PHASE_4.md` (Fase 4) e
`SECURITY_MANUAL_TESTS.md` (checklist manual acumulado das fases anteriores, ainda pendente de
execução pelo usuário).

## Resumo executivo

Esta fase tentou responder, com execução real (não leitura de código), a pergunta central: **o
Cofre funciona com segurança no uso cotidiano, ou só tem código e testes que parecem corretos?**

O ambiente desta sessão **não tem um driver de automação de UI para Tauri** (não existe
equivalente pronto ao Playwright/Selenium para uma janela nativa WebView2 — montar
`tauri-driver`+`msedgedriver` do zero estava fora do escopo desta sessão) e **não é seguro** eu
mesmo forçar eventos de SO (Win+L, suspender, hibernar) numa máquina em uso, sem que o usuário
esteja presente e ciente. Isso significa que a fração da Seção 4-58 do pedido que depende de
clicar na janela real ou de eventos físicos do Windows **não pôde ser executada por mim nesta
sessão** — exatamente a mesma limitação que as Fases 3 e 4 já haviam documentado com honestidade.

Dentro do que era executável sem interação humana, esta fase:

1. **Rodou de verdade** (não simulou): `cargo check`, `cargo test --lib` (72/72, ver abaixo),
   `cargo clippy`, `npx tsc --noEmit`, `npm run build`, `npm audit`, `cargo build --release`, e o
   **build de produção completo** (`npm run tauri build`) — gerando os dois instaladores reais
   (`.msi` e `.exe` NSIS) que o usuário empacotaria para distribuir/instalar.
2. **Executou o app de verdade** duas vezes nesta máquina Windows real: `npm run tauri dev`
   (compilou, Vite subiu, o processo `tauri-app.exe` ficou rodando, sem erro em stderr) e o
   executável `release/tauri-app.exe` isolado (rodou silenciosamente, sem log, sem crash,
   ~29 MB de working set — consistente com as Fases 3/4).
3. **Encontrou um cofre pré-existente do desenvolvedor** no diretório de dados do app
   (`%APPDATA%\<identifier>\vault.db`) e, antes de qualquer outro teste, **fez uma cópia de
   segurança** dele para um local fora do projeto [caminho local removido], sem apagar nem
   sobrescrever nada. Detalhes na seção "Cofre pré-existente no diretório de dados" abaixo —
   **achado importante sobre como testar com segurança sem tocar num cofre real**.
4. **Fechou uma lacuna de testes automatizados real** que as 4 fases anteriores tinham deixado em
   aberto: `security_questions.rs` (fluxo de recuperação por perguntas) tinha **zero testes
   automatizados** antes desta fase, e `recovery_key.rs` só tinha 1 (só testava o "gate" de cofre
   bloqueado, não o desbloqueio de verdade). Escrevi 11 testes novos que exercitam o fluxo
   completo com dados sintéticos: Recovery Key certa recupera a DEK real, Recovery Key errada
   falha sem alterar `vault_meta`, gerar uma nova chave exige a senha mestra certa, respostas de
   segurança corretas/erradas/parciais, lockout após 5 falhas, lockout expira e libera de novo, e
   trocar a senha mestra após uma recuperação mantém a mesma DEK (mesmos dados). Ver seção
   "Testes automatizados" para o detalhe técnico — **72/72 testes passando**, incluindo os 61 já
   existentes (nenhuma regressão).
5. **Não pôde executar**, e documenta aqui sem maquiagem: qualquer fluxo que dependa de clicar na
   janela real (criar conta pela UI, revelar/copiar senha, abrir modais), qualquer evento de SO
   (Win+L, suspender, hibernar, fechar tampa), o teste de clipboard "ao vivo", a simulação de XSS
   via DevTools real, e o ciclo de backup/restore via diálogo de arquivo do SO. Um protocolo
   manual detalhado e pronto para uso está em `SECURITY_MANUAL_TESTS.md` (16 itens, já existente
   das Fases 3/4) — esta fase não duplica esse documento, só confirma que ele continua sendo
   exatamente o que falta para fechar a validação.

**Classificação desta fase: BEM ENDURECIDO PARA USO PESSOAL, com um bloco de testes manuais
explicitamente pendente antes de confiar dados reais de forma irrestrita.** Ver seção
"Classificação final" para a justificativa completa — mantida em relação às Fases 2-4 porque nada
regrediu e evidência nova e real foi adicionada, mas **não posso, com honestidade, elevar a
classificação** enquanto os itens de `SECURITY_MANUAL_TESTS.md` continuarem sem confirmação do
usuário.

## Ambiente testado

- Windows 11 real, desktop interativo disponível (mesma máquina das Fases 3/4).
- `cargo 1.98.0`, Rust/Tauri 2.11.x (via `rustup`, não estava no `PATH` desta sessão de shell —
  precisei referenciar `$env:USERPROFILE\.cargo\bin` diretamente; não é um problema do projeto).
- Node/npm já configurados no projeto (Vite 7.3.6, React 19, TypeScript ~5.8).
- **Sem** `tauri-driver`/`msedgedriver`/Playwright configurados — confirmado por ausência total
  de arquivos de config desse tipo no repositório (mesma limitação já documentada nas Fases 3/4).

## Versão/build

- Branch `main`, working tree com mudanças não commitadas (o próprio objeto desta tarefa):
  `platforms.rs`, `backup.rs`, `vault.rs`, `db.rs`, `tauri.conf.json`, `src/types/index.ts` (feature
  de plataformas/imagens padrão, já existente antes desta fase) + `recovery_key.rs`/
  `security_questions.rs` (testes novos desta fase, ver "Correções realizadas").
- `cargo build --release`: sucesso, binário em
  `[diretório de build local removido]\release\tauri-app.exe`.
- `npm run tauri build` (build de produção completo, com bundling): sucesso —
  `Cofre de Contas_0.1.0_x64_en-US.msi` (7,3 MB) e `Cofre de Contas_0.1.0_x64-setup.exe` (4,9 MB),
  ambos gerados nesta sessão a partir do código atual.

## Testes automatizados

| Comando | Resultado | Detalhe |
|---|---|---|
| `cargo check` | ✅ limpo | sem erros/warnings de compilação |
| `cargo test --lib` | ✅ **72/72 passando** | 61 herdados (Fases 1-4) + 11 novos desta fase, 0 falhas |
| `cargo clippy --lib` | ✅ 2 warnings pré-existentes | `accounts.rs` (tipo complexo), `migration.rs` (`.into_iter()` explícito) — ambos já documentados como aceitáveis na Fase 3, não relacionados a segurança, não introduzidos por esta fase |
| `npx tsc --noEmit` | ✅ limpo | sem erros de tipo |
| `npm run build` | ✅ sucesso | bundle 337,59 kB JS / 25,91 kB CSS (consistente com Fase 4) |
| `npm audit` | ✅ **0 vulnerabilidades** | |
| `cargo build --release` | ✅ sucesso | 1 warning benigno de linker (geração de `.dll.lib`/`.dll.exp`, mesmo aviso das Fases 3/4, não relacionado ao código) |
| `npm run tauri build` | ✅ sucesso | gerou `.msi` e `.exe` (NSIS) reais — primeira vez que uma das fases desta auditoria confirma o **pacote de distribuição completo**, não só o binário |

Não havia `vitest`/`jest` configurado para o frontend (mesma observação já feita na Fase 2) — não
adicionei como efeito colateral desta validação, conforme a regra de não introduzir features novas
nesta fase.

### Testes novos desta fase (o que estava faltando)

Antes desta fase, `security_questions.rs` (o módulo inteiro do fluxo de recuperação por perguntas)
tinha **zero testes automatizados** — as Fases 1-4 validaram esse fluxo só por leitura de código.
`recovery_key.rs` tinha 1 teste, que só confirmava que o cofre bloqueado nega acesso, não que o
desbloqueio por Recovery Key de fato funciona. Isso significa que, apesar de 4 fases de auditoria,
**a seção mais crítica pedida nesta última fase (Recovery Key, perguntas de segurança, lockout)
nunca tinha evidência automatizada real** — só a garantia, por leitura de código, de que a lógica
"parecia certa". Corrigido nesta fase, sem alterar nenhum comportamento de produção (extraí a
lógica já existente para funções puras `_core`, testáveis com `rusqlite::Connection::open_in_memory()`
— mesmo padrão já usado em `backup.rs`/`properties.rs`/`vault.rs` desde as fases anteriores; os
`#[tauri::command]` continuam com a mesma assinatura e comportamento externo):

| Teste novo | O que prova |
|---|---|
| `recovery_key::correct_recovery_key_unlocks_and_recovers_the_real_dek` | Recovery Key certa devolve **exatamente** a DEK real do cofre (não uma cópia/aproximação) |
| `recovery_key::wrong_recovery_key_fails_cleanly_without_altering_vault_meta` | chave errada → erro genérico, `recovery_key_wrapped_dek` no banco **não muda um único byte** |
| `recovery_key::generating_a_new_recovery_key_rejects_wrong_current_password` | gerar uma nova chave com senha mestra errada é rejeitado, e a chave antiga **continua válida** (não foi invalidada por engano) |
| `recovery_key::generating_a_new_recovery_key_with_correct_password_invalidates_the_old_one` | com a senha certa, a chave nova funciona e a antiga **para de funcionar** |
| `security_questions::correct_answers_reconstruct_the_real_dek` | 3 respostas corretas (Shamir) reconstroem a mesma DEK real |
| `security_questions::answers_are_normalized_before_checking` | capitalização/espaços não impedem uma recuperação legítima |
| `security_questions::wrong_answer_is_rejected_cleanly_without_altering_state` | resposta errada → falha limpa, `vault_meta.dek_check` **não muda** |
| `security_questions::partially_correct_answers_below_threshold_are_rejected` | 2 de 3 corretas (abaixo do limiar) falha do mesmo jeito que todas erradas — não existe "quase recuperado" |
| `security_questions::five_failed_attempts_lock_out_even_a_subsequent_correct_attempt` | 5 falhas seguidas ativam lockout, e **mesmo respostas certas** são recusadas durante a janela de bloqueio |
| `security_questions::lockout_expires_and_correct_answers_work_again_after_the_window` | depois que a janela de 15 min expira, respostas corretas voltam a funcionar |
| `security_questions::reset_master_password_after_recovery_invalidates_old_password_and_keeps_the_same_dek` | trocar a senha mestra após uma recuperação: senha antiga passa a falhar, nova funciona, **a DEK (e portanto todos os dados já cifrados) continua idêntica** |

## Cofre pré-existente no diretório de dados — achado importante

Ao iniciar o app (`npm run tauri dev` e depois o `.exe` de release) para confirmar que ambos sobem
sem erro, descobri que **ambos apontam para o mesmo `app_data_dir` físico** —
`%APPDATA%\<identifier>\vault.db` — porque o Tauri não separa automaticamente "perfil de dev" de
"perfil de produção"; os dois usam o identificador do app (`identifier` em
`src-tauri/tauri.conf.json`) e portanto o mesmo diretório de dados. Na máquina de desenvolvimento
já existia ali um cofre real, criado pelo desenvolvedor antes desta etapa.

Antes de fazer qualquer outra coisa, esse banco e a pasta `images/` foram copiados para um local
de backup fora do projeto [caminho local removido]. A inspeção foi **somente leitura**, sem
decifrar nenhum campo. [Detalhes sobre esse cofre, como datas e contagens de registros, foram
removidos desta cópia pública.]

As únicas ações executadas contra esse banco foram `vault_status`/`init_schema`/
`provision_default_platform_images` (chamadas automaticamente ao abrir o app, mesmo sem
desbloquear), que são idempotentes. **Nenhuma conta foi criada, nenhuma Recovery Key foi gerada e
`vault_meta` só foi lido.** A cópia de backup existe como rede de segurança extra, não porque algo
tenha dado errado.

**Recomendação prática para os testes manuais que restam:** como dev e release apontam para o
mesmo `vault.db`, use o procedimento abaixo para seguir o protocolo de `SECURITY_MANUAL_TESTS.md`
sem nenhum risco a um cofre real:

```
1. Feche o Cofre completamente (dev e/ou release).
2. Renomeie temporariamente a pasta:
   %APPDATA%\<identifier>  →  <identifier>.REAL_BACKUP
3. Abra o app — ele vai tratar como instalação nova (tela de "criar senha mestra").
4. Cadastre o cofre sintético (ver "Dados sintéticos sugeridos" abaixo) e rode todo o protocolo
   de `SECURITY_MANUAL_TESTS.md` (lock manual, Win+L, suspend, hibernate, clipboard, XSS via
   DevTools, rate limiter, etc.) à vontade.
5. Ao terminar, feche o app, apague a pasta de teste criada em `%APPDATA%\<identifier>`,
   e renomeie `<identifier>.REAL_BACKUP` de volta para `<identifier>` — o cofre real volta
   exatamente como estava.
```

Isso é mais seguro do que confiar em "não vou clicar em nada que toque o cofre real por engano" —
fisicamente não há como um teste tocar o vault errado se a pasta real estiver temporariamente fora
do caminho esperado.

## Dados sintéticos sugeridos (para os testes manuais)

Exatamente os valores pedidos, prontos para copiar/colar durante o protocolo manual:

```
Conta: SECURITY_TEST_INSTAGRAM
Username: security_test_user
Password: SECURITY_TEST_PASSWORD_93821
Notes: SECURITY_TEST_NOTE_58321
Propriedade sensível (ex.: "Chave de API"): SECURITY_TEST_APIKEY_82917
2FA (telefone/app/notas, à escolha): SECURITY_TEST_2FA_18273
```

Mais: 1 projeto, 1 tag, 1 propriedade não sensível, 1 pergunta de segurança sintética (resposta não
óbvia, ex. um texto aleatório — não uma resposta real do usuário), e gerar uma Recovery Key (o
texto dela só aparece uma vez — anote para o teste de recuperação e descarte depois).

## Testes manuais (executados nesta sessão vs. pendentes)

| Item do pedido | Executado nesta sessão? | Evidência |
|---|---|---|
| `npm run tauri dev` sobe sem erro | ✅ Sim | processo `tauri-app.exe` rodando (~33 MB), sem erro em stderr, sem `native_lock` falhando |
| Release (`cargo build --release` + `npm run tauri build`) compila e roda | ✅ Sim | binário + `.msi`/`.exe` gerados; `release/tauri-app.exe` executado isoladamente, silencioso, sem crash |
| Criar/editar conta pela UI real, persistência, restart | ❌ Não | requer clique real — protocolo em `SECURITY_MANUAL_TESTS.md` item 13 |
| Copiar senha (botão real) | ❌ Não | idem, item 10 |
| Clipboard auto-clear (não apaga texto não relacionado) | ❌ Não (lógica já coberta por leitura de código nas Fases 1-2, não por clique real) | item 10 |
| Revelar/esconder senha na UI | ❌ Não | item 13 |
| Propriedade sensível via UI | ❌ Não | item 13 |
| Teste de posse (`account_id` cruzado) | ✅ Sim, via teste automatizado | `properties::reveal_rejects_property_belonging_to_another_account` (já existia, revalidado: 72/72) |
| Notes: persistência + ausência de plaintext no SQLite | ✅ Sim (plaintext), ❌ Não (fluxo de UI) | teste `synthetic_markers_never_appear_in_plaintext_on_disk` usa os **mesmos marcadores exatos** pedidos nesta fase |
| 2FA: idem | ✅ Sim (plaintext) / ❌ Não (UI) | mesmo teste acima |
| Recovery Key: gerar/recuperar/senha errada/reautenticação | ✅ Sim, via 4 testes automatizados novos | ver tabela "Testes novos" |
| Security Questions: correta/errada/parcial/lockout/reset | ✅ Sim, via 7 testes automatizados novos | ver tabela "Testes novos" |
| Master Password Change preserva DEK | ✅ Sim (via teste `reset_master_password_after_recovery_...`) | mesma lógica de `change_master_password`, já coberta indiretamente |
| Lock manual + tentativa de IPC direto | ✅ Sim, por leitura de código + testes de gate (`with_dek`/`is_unlocked`) | consistente com Fases 2-4; não testado via DevTools real nesta sessão |
| DevTools/manipulação de frontend não desbloqueia o backend | ✅ Sim, por leitura de código (estado só existe no processo Rust) | não testado clicando de verdade |
| XSS simulado (locked/unlocked) | ❌ Não (exige DevTools real) | protocolo em `SECURITY_MANUAL_TESTS.md` item 16, com passo a passo exato |
| Rate limiter (25/10s) | ✅ Sim, via teste automatizado com janela reduzida | `state::reveal_limiter_blocks_after_threshold_and_recovers` |
| CSP efetiva | ✅ Parcial (config estática confirmada) / ❌ Não (inspeção de rede na WebView real) | ver seção CSP abaixo |
| Win+L / Suspend / Hibernate / Fechar tampa | ❌ Não | `SECURITY_MANUAL_TESTS.md` itens 1-4 — **não executo eventos de SO na máquina do usuário sem ele presente**, mesma decisão documentada nas Fases 3/4 |
| Lock-on-minimize / Auto-lock | ❌ Não | itens 5-8 |
| Restart/crash não restaura sessão desbloqueada | ✅ Sim, por design (DEK só existe em RAM do processo — encerrar o processo a libera; não há nenhum mecanismo de persistência de sessão) | item 11 |
| Backup: round-trip, senha errada, adulterado, truncado | ✅ Sim, via testes automatizados já existentes, revalidados | `full_round_trip_preserves_every_table_and_ciphertext_byte_for_byte`, `wrong_backup_password_is_rejected`, `tampered_backup_file_is_rejected_without_touching_the_database`, `truncated_or_garbage_file_is_rejected_not_panicking` |
| Backup via diálogo de arquivo real (export/import na UI) | ❌ Não | item 12 |
| Imagens padrão (novos assets) | ✅ Sim, via 5 testes automatizados (Fase atual, já existentes antes desta sessão) | `db::tests::*` |
| Plaintext scan no SQLite | ✅ Sim | mesmo teste de marcadores sintéticos |
| Logs (console/stdout/stderr) sem segredo | ✅ Sim | log do `npm run tauri dev`/release não imprime nada além de mensagens de build; grep herdado das Fases 1-4 confirma ausência de `println!`/`console.log` de segredo no código |
| DevTools indisponível em release | ✅ Parcial (confirmado estaticamente: sem feature `devtools`, sem override de `debug_assertions` em `[profile.release]`) / ❌ Não (F12 real na janela de release) | item 9 |
| Permissões (capabilities) sem SQL/fs/shell genérico | ✅ Sim | `capabilities/default.json` inspecionado diretamente |

## Password / Reveal / Copy

Arquitetura inalterada desde a Fase 4: `reveal_account_password(id)`/`copy_account_password(id,
clear_after_seconds?)` — nenhum ciphertext trafega da/para a WebView, `copy_*` nunca devolve o
plaintext ao JS (decifra e escreve no clipboard inteiramente no Rust). Revalidado por leitura de
código (arquivo não foi alterado nesta fase) e pelo teste automatizado
`accounts::create_and_reveal_password_round_trip` (72/72). **Não testado via clique real** — ver
tabela acima.

## Clipboard

Lógica inalterada (`clipboard.rs`, Fase 1-2): só limpa se o conteúdo ainda for exatamente o que o
app copiou. **Não testado ao vivo** nesta sessão (exige copiar de verdade e esperar o timer) — item
10 do protocolo manual.

## Properties / Notes / 2FA

Ownership (`account_id` cruzado) e ausência de ciphertext em massa nas listagens — inalterados
desde a Fase 4, revalidados pelos testes já existentes (72/72). Plaintext scan confirma que
`SECURITY_TEST_NOTE_58321`/`SECURITY_TEST_2FA_18273`/`SECURITY_TEST_APIKEY_82917` nunca aparecem
em claro num `.db` real gravado em disco.

## Recovery Key

Ver "Testes novos desta fase" — agora com evidência automatizada de ponta a ponta, não só leitura
de código. Reautenticação por senha mestra confirmada funcionando (rejeita senha errada sem
invalidar a chave existente).

## Security Questions

Ver "Testes novos desta fase". Lockout de 5 tentativas confirmado automaticamente, incluindo o
caso importante de que **uma tentativa correta durante o lockout ainda é recusada** (o bloqueio é
por tempo, não descontado por acerto) e que o lockout expira corretamente depois da janela.

## Master Password Change

Coberto indiretamente pelo teste `reset_master_password_after_recovery_invalidates_old_password_and_keeps_the_same_dek`
— confirma que a DEK (e portanto todos os segredos já cifrados) permanece idêntica após uma troca
de senha, sem recriptografia desnecessária. `change_master_password` (o comando usado no fluxo
normal, não após recuperação) usa exatamente a mesma lógica de re-wrap, já validada nas Fases 1-2.

## Lock Manual / Win+L / Suspend / Hibernate / Auto-Lock / Lock-on-Minimize

Nenhum destes foi executado interativamente nesta sessão — mesma limitação documentada nas Fases
3-4 (sem driver de UI; eventos de SO não devem ser forçados sem o usuário presente). O hook nativo
(`native_lock.rs`) e a lógica de relógio de parede (`useAutoLock.ts`) não foram alterados por
nenhuma mudança desta fase (nem das mudanças de plataformas/imagens já existentes) — permanecem
exatamente como a Fase 3 os deixou. **Protocolo pronto em `SECURITY_MANUAL_TESTS.md`, itens 1-8.**

## XSS — Locked / Unlocked

Análise por código inalterada desde a Fase 4 (nenhum arquivo relevante a este risco foi tocado
nesta sessão): com o cofre bloqueado, nenhum dos 8 commands públicos expõe segredo. Com o cofre
desbloqueado, `reveal_account_password`/`reveal_sensitive_property` continuam sujeitos ao rate
limiter (25/10s, agora também coberto por teste automatizado da fronteira exata do limite);
`get_account_notes`/`get_account_two_factor_details` continuam **sem** rate limit (decisão
consciente documentada na Fase 4). **Não testado via DevTools real** — protocolo pronto em
`SECURITY_MANUAL_TESTS.md`, item 16.

## Rate Limit

Confirmado automaticamente (`state::reveal_limiter_blocks_after_threshold_and_recovers`, já
existente, revalidado): bloqueia exatamente na chamada seguinte ao limite, libera após a janela
expirar. **Não é uma barreira criptográfica** — é fricção contra um dump automatizado, conforme já
documentado na Fase 4 e reafirmado aqui sem suavizar.

## CSP / Exfiltração

`tauri.conf.json` inspecionado diretamente nesta sessão — a CSP da Fase 2 continua **exatamente
igual**, não foi alterada por nenhuma mudança recente:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' asset: http://asset.localhost https://asset.localhost data:;
font-src 'self';
connect-src 'self' ipc: http://ipc.localhost ws://localhost:1420 http://localhost:1420;
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
```

Testado nesta sessão: o HTML servido pelo Vite dev server (`http://localhost:1420/`) foi buscado
diretamente — confirma ausência de qualquer script remoto/inline além do próprio HMR do Vite (que
não existe em produção). **Isso não é a mesma coisa que confirmar a CSP sendo de fato aplicada
dentro do processo WebView2 real** (a CSP do Tauri é injetada pelo runtime do webview, não
aparece no HTML cru servido pelo Vite) — essa confirmação exigiria abrir o DevTools real e checar
a aba Network/Console, que não pude fazer nesta sessão. **Item pendente do protocolo manual**
(`SECURITY_MANUAL_TESTS.md` item 16, passo 9).

## Backup

Todos os testes automatizados já existentes (round-trip completo, senha errada, arquivo
adulterado, arquivo truncado) foram revalidados nesta sessão (72/72, nenhuma regressão). O ciclo
via diálogo de arquivo real (exportar → novo ambiente → importar → comparar) **não foi executado**
— protocolo em `SECURITY_MANUAL_TESTS.md`, item 12.

## SQLite Plaintext Search

Executado (teste automatizado, não simulação): `commands::backup::tests::synthetic_markers_never_appear_in_plaintext_on_disk`
grava um `.db` real em disco com exatamente os 5 marcadores pedidos nesta fase
(`SECURITY_TEST_PASSWORD_93821`, `SECURITY_TEST_NOTE_58321`, `SECURITY_TEST_2FA_18273`,
`SECURITY_TEST_APIKEY_82917`, mais `SECURITY_TEST_RECOVERY_73918` para a pergunta de segurança) e
confirma que nenhum aparece em texto puro nos bytes crus do arquivo — arquivo de teste apagado ao
final da execução do teste (não deixado no disco).

## Logs

`npm run tauri dev` e o `.exe` de release não imprimiram nada além das mensagens de build do
Cargo/Vite — nenhum dado de conta, senha, Recovery Key ou resposta de segurança nos logs
observados nesta sessão.

## Release Build

`cargo build --release`: sucesso. `npm run tauri build`: sucesso, gerando os dois instaladores
reais (`.msi` 7,3 MB, NSIS `.exe` 4,9 MB). O `release/tauri-app.exe` isolado foi executado e
confirmado rodando sem erro, sem log, ~29 MB de working set.

## DevTools

Confirmado **estaticamente** (não interativamente): `Cargo.toml` não habilita a feature
`devtools` do crate `tauri`, e não há `[profile.release]` sobrescrevendo `debug_assertions` — a
mesma análise de código-fonte de dependências que a Fase 3 já tinha feito continua válida (nenhum
arquivo relevante a isso mudou). **Não tentei abrir F12 no `.exe` de release real** nesta sessão —
item 9 do protocolo manual continua sendo a confirmação empírica final.

## Bugs encontrados

Nenhum bug de segurança novo foi encontrado nesta fase. O único "achado" foi de **processo/
ambiente**, não de código: dev e release compartilham o mesmo `app_data_dir`, o que exige cuidado
ao testar manualmente para não misturar dados sintéticos com o cofre real do usuário — documentado
acima com um procedimento de troca seguro (renomear a pasta temporariamente).

## Bugs corrigidos

Nenhum — não havia bug a corrigir. O trabalho desta fase foi **fechar uma lacuna de cobertura de
testes** (Recovery Key/perguntas de segurança sem testes automatizados de ponta a ponta), não
consertar um defeito.

## Riscos residuais

Idênticos aos já documentados nas Fases 2-4, nenhum novo introduzido, nenhum eliminado:

1. XSS com o cofre desbloqueado ainda pode revelar qualquer segredo, um por vez, throttled pelo
   rate limiter (25/10s) para senha/propriedade sensível — inerente ao modelo de confiança do
   Tauri, não corrigível sem uma reformulação de UX maior (fora do escopo desta fase, que era
   validação, não redesenho).
2. `get_account_notes`/`get_account_two_factor_details` não passam pelo rate limiter.
3. Perguntas de segurança dependem da entropia da resposta escolhida pelo usuário.
4. Sem hook nativo dedicado a hibernação (o mesmo hook de suspensão provavelmente cobre o caso,
   não verificado empiricamente).
5. `projects.notes` continua em texto puro (lacuna documentada desde a Fase 2, fora do escopo
   desta e das fases anteriores).
6. **Novo desta fase, de processo:** dev e release apontam para o mesmo `app_data_dir` — sem uma
   forma nativa de "perfil de teste" separado, o usuário precisa mover a pasta manualmente para
   testar com segurança (procedimento documentado acima).
7. **A validação real de produto (clique na UI, eventos de SO) continua pendente** — esta fase
   reduz, mas não elimina, a lacuna "código parece certo" vs. "testado como produto". O protocolo
   de `SECURITY_MANUAL_TESTS.md` é o que falta para fechar isso de verdade.

## Classificação final

> **BEM ENDURECIDO PARA USO PESSOAL — com testes manuais de UI/SO explicitamente pendentes.**

Não elevo a classificação em relação às Fases 2-4 apesar da evidência nova, porque a pergunta
central desta fase ("é um produto real testado, ou só código que parece certo?") **ainda não pode
ser respondida com um "sim" completo** — a arquitetura de backend está agora mais testada do que
nunca (72 testes automatizados cobrindo inclusive o fluxo de recuperação, que antes não tinha
nenhum), o build de produção real funciona e foi executado, mas os fluxos que só existem na
interação humana com a janela real (clicar, copiar, ver o clipboard, apertar Win+L, abrir DevTools)
continuam sem confirmação empírica nesta sessão. Não rebaixo a classificação porque nada de errado
foi encontrado — só não posso honestamente chamar de "testado como produto" o que ainda depende de
mãos humanas na janela real.

## A pergunta mais importante

> **Você colocaria credenciais pessoais reais neste Cofre, considerando o threat model
> documentado?**

**Sim, com uma condição explícita: só depois de você mesmo rodar o protocolo de
`SECURITY_MANUAL_TESTS.md` pelo menos uma vez** (Win+L, suspender, clipboard e a simulação de XSS
via DevTools são os itens mais importantes dessa lista) **usando o procedimento de troca de pasta
descrito acima**, para não arriscar um cofre real já existente.

**Contra o que ele protege, com evidência real desta fase e das anteriores:**
- Roubo do `vault.db`/pasta de dados sem a senha mestra: senha, notes, 2FA e propriedades
  sensíveis continuam cifrados com XChaCha20-Poly1305 sob uma DEK protegida por Argon2id — nenhum
  marcador sintético apareceu em claro no arquivo, confirmado por teste automatizado real.
- Chamada de IPC direta com o cofre bloqueado: nenhum command sensível expõe segredo (verificado
  por leitura de código de todos os 70+ commands + testes de gate).
- Backup roubado/adulterado/truncado: rejeitado de forma segura, sem corromper o banco atual
  (testes automatizados revalidados).
- Recovery Key/perguntas de segurança erradas: falham sem corromper `vault_meta` nem alterar a
  configuração existente (novo nesta fase, com evidência automatizada real).

**Contra o que ele NÃO protege (sem mudança em relação às Fases 2-4, reafirmado sem suavizar):**
- Um XSS ativo enquanto o cofre está desbloqueado ainda pode, com paciência, revelar qualquer
  segredo que a UI legítima também revelaria — mais lento (rate limiter), mas não impedido.
- Malware/processo com privilégios administrativos, keylogger, ou um debugger com acesso à
  memória do processo — fora do threat model deste tipo de aplicação, documentado desde a Fase 3.

**Risco que ainda existe e que só o usuário pode fechar:** os itens de `SECURITY_MANUAL_TESTS.md`
não confirmados empiricamente (Win+L, suspend, hibernate, clipboard ao vivo, DevTools em release,
lock-on-minimize, auto-lock por relógio real). O código foi lido e testado onde era possível; a
confirmação final de que a janela real se comporta como o código promete continua sendo sua.
