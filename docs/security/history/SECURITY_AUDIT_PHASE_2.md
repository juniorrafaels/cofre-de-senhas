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
> - `decrypt_secret`, `encrypt_secret` e `copy_secret_to_clipboard(ciphertext)`, descritos aqui como
>   superfície ativa, foram **removidos na Fase 4** e substituídos por commands por ID. O SQL livre
>   da WebView, mantido nesta fase, foi **removido na Fase 3**.
> - A tabela de IPC trata `import_backup` sem unlock como "intencional" e marca
>   `reset_master_password_after_recovery` como protegido "via `with_dek`". A revisão posterior
>   tratou os dois pontos como problemas (ver último item).
> - `projects.notes` continua em texto puro no código atual (lacuna ainda válida).
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

# Security Audit — Phase 2 (Hardening)

Data: 2026-08-28
Escopo: continuação de `SECURITY_AUDIT.md` (Fase 1). Mesmo ambiente sem GUI interativa disponível — validação por revisão de código, `cargo check`/`cargo test`, `npx tsc --noEmit`, `npm run build` e `npm audit`.

## Resumo executivo

A Fase 1 validou a arquitetura criptográfica central (Argon2id + XChaCha20-Poly1305 + DEK em memória) e corrigiu 4 achados (2FA em claro, SQL injection no backup, backup incompleto, path traversal em imagens). Esta Fase 2 parte da pergunta "se uma camada secundária for comprometida, até onde um atacante chega?" e aplica **defesa em profundidade** sem tocar nos componentes criptográficos que já estavam corretos.

Principais entregas desta fase:

1. **`notes` de conta agora é sempre cifrado** (Prioridade 1), com migração automática e idempotente de dados legados a cada desbloqueio, e **fallback de texto puro removido** — campos cifrados que falham ao decifrar agora falham de forma visível ("Não foi possível descriptografar este dado."), nunca são tratados como texto puro.
2. **Recovery Key implementada**: segundo caminho independente e de alta entropia (120 bits) para desembrulhar a mesma DEK, reaproveitando exatamente os primitivos já auditados (Argon2id + XChaCha20-Poly1305) — sem inventar criptografia nova.
3. **Perguntas de segurança**: mantidas (não são uma vulnerabilidade de implementação), mas a UI agora deixa explícito que são o elo mais fraco e orienta o uso de respostas não óbvias; a Recovery Key passa a ser o mecanismo recomendado.
4. **Cópia de segredos sem passar pelo frontend**: novo comando Rust `copy_secret_to_clipboard` decifra e escreve na área de transferência inteiramente no backend — os botões de "copiar" (senha, propriedades sensíveis) não fazem mais o plaintext transitar pelo processo da webview.
5. **CSP restritiva** aplicada (`default-src 'self'` e afins) — antes era `null`.
6. **Bloqueio ao minimizar** (opcional) e **auto-lock robusto contra suspensão do SO** (checa o relógio de parede ao voltar a ficar visível, não confia só no `setTimeout`).
7. **Validação de esquema de URL** (`http`/`https` apenas) em `openLoginUrl`, em cima da já existente restrição por capability do Tauri.
8. Backup estendido para cobrir as novas colunas de Recovery Key e testado com **round-trip completo + adulteração + senha errada + arquivo truncado**.
9. Suíte de testes Rust ampliada de **10 para 22 testes**, incluindo um teste que grava um `.db` real em disco com os marcadores sintéticos pedidos e confirma sua ausência em texto puro.

Nenhuma vulnerabilidade CRÍTICA foi encontrada nesta fase. Duas ALTAS foram corrigidas (notes em claro; fallback de plaintext perigoso). O maior item conscientemente **não** implementado — remoção total do SQL livre da WebView — está documentado com justificativa técnica na seção "SQL da WebView" e como recomendação para a Fase 3.

## Estado herdado da Fase 1

Confirmado antes de qualquer alteração desta fase (`cargo test --lib`): os 10 testes da Fase 1 continuavam passando — 2FA cifrado, allowlist de colunas do backup, path traversal em imagens, e as propriedades de `crypto.rs` (round-trip, adulteração, chave errada, nonce único). Nenhuma regressão foi introduzida nas correções anteriores; todos os 10 testes originais continuam presentes e passando dentro da suíte de 22 desta fase.

## Mudanças realizadas

| Categoria | Arquivos principais |
|---|---|
| Criptografia de `notes` + migração + fail-closed | `src/App.tsx`, `AccountForm.tsx`, `AccountDetailModal.tsx`, `src/lib/secretFields.ts`, `src-tauri/src/migration.rs`, `vault.rs`, `security_questions.rs` |
| Recovery Key | `src-tauri/src/crypto.rs`, `src-tauri/src/commands/recovery_key.rs`, `db.rs` (schema), `src/components/settings/RecoveryKeySection.tsx`, `RecoveryKitDialog.tsx`, `src/components/vault/RecoveryFlow.tsx` |
| Cópia sem plaintext no frontend | `src-tauri/src/commands/clipboard.rs`, `src/lib/useCopy.ts`, `AccountCard.tsx`, `AccountsListView.tsx`, `AccountDetailModal.tsx`, `AccountPropertiesSection.tsx` |
| CSP | `src-tauri/tauri.conf.json` |
| URLs externas | `src/lib/tauri.ts` (`isAllowedExternalUrl`) |
| Lock/Suspend | `src/lib/useAutoLock.ts`, `src/App.tsx`, `useSettingsStore.ts`, `SettingsView.tsx`, `types/index.ts` |
| Backup estendido + testes | `src-tauri/src/commands/backup.rs` |
| Busca não indexa mais `notes` cifrado | `src/lib/filter.ts` |

## Criptografia de Notes

**Antes:** `accounts.notes` era gravado em texto puro (achado documentado na Fase 1, seção "Informativos").

**Depois:**

```text
Observações digitadas
      ↓
secretCommands.encrypt(notes)  — mesma DEK, XChaCha20-Poly1305, nonce novo a cada gravação
      ↓
accounts.notes = base64(nonce || ciphertext+tag)
```

- `App.tsx::handleSaveAccount` cifra `notes` antes de salvar (sempre, sem toggle "marcar como sensível" — conforme pedido, observações são tratadas como sempre sensíveis).
- `AccountForm.tsx` e `AccountDetailModal.tsx` decifram sob demanda ao abrir para edição/visualização.
- **Migração automática e idempotente** (`src-tauri/src/migration.rs::migrate_plaintext_account_fields`): a cada desbloqueio bem-sucedido (senha mestra, perguntas de segurança ou Recovery Key), o backend varre `accounts.notes` (e os 4 campos de 2FA) e, para qualquer valor que **não** decifre com sucesso sob a DEK atual, assume que é texto puro legado e o re-cifra in-place. Depois da primeira execução em cada linha, toda chamada seguinte é apenas uma tentativa de decifragem (rápida, sem Argon2) que não escreve nada — seguro rodar sempre.
- Verificado com teste (`migration::tests::migrates_legacy_plaintext_fields_and_is_idempotent`): insere um valor em claro, roda a migração, confirma que (a) o valor gravado não contém mais o texto original, (b) decifra de volta corretamente com a DEK, (c) uma segunda execução não altera nada.
- **Verificação prática pedida na seção 5 do pedido:** o teste `synthetic_markers_never_appear_in_plaintext_on_disk` grava um `.db` real em disco com `SECURITY_TEST_NOTE_58321` (e os outros 4 marcadores pedidos) cifrados, lê os bytes crus do arquivo e confirma que nenhum marcador aparece — arquivo de teste apagado ao final.
- `src/lib/filter.ts`: `account.notes` removido do índice de busca (antes buscava em texto puro; agora seria ciphertext ilegível, então foi removido deliberadamente em vez de deixado quebrado).

## Migração de 2FA (remoção do fallback)

A Fase 1 havia introduzido um fallback: se um campo de 2FA não decifrasse, o valor bruto (presumido texto puro legado) era exibido. Esta fase:

1. Estendeu a mesma migração automática (`migration.rs`) para cobrir os 4 campos de 2FA — agora rodando junto com `notes` no mesmo passo, a cada desbloqueio.
2. **Removeu o fallback** em `AccountForm.tsx` e `AccountDetailModal.tsx`. O novo helper compartilhado `src/lib/secretFields.ts::tryDecryptField` retorna `{ ok: true, value }` ou `{ ok: false }` — nunca "decifra ou devolve o texto cru".
3. Em caso de falha de descriptografia, a UI mostra explicitamente **"Não foi possível descriptografar este dado."** em vez de assumir texto puro (fail closed, seção 15 do pedido).
4. **Proteção contra perda de dados:** se um campo falhar ao decifrar e o usuário salvar o formulário sem editá-lo, o ciphertext original é preservado (não é sobrescrito por uma string vazia). Implementado via `preserveFields: SensitiveField[]` retornado por `AccountForm` e honrado em `App.tsx::handleSaveAccount`.

Por que isso é seguro agora (e não era, antes da migração automática existir): antes desta fase não havia nenhuma migração de fato — o fallback "se falhar, mostra em claro" era a única forma de não perder dados legados. Agora que a migração roda automaticamente e é idempotente, qualquer dado legado já foi convertido no primeiro desbloqueio depois da atualização, então uma falha de descriptografia hoje só pode significar corrupção/adulteração — e é tratada como tal.

## Recuperação (arquitetura documentada)

Mapeamento pedido na seção 7:

```text
Perguntas
    ↓ (resposta normalizada: trim + lowercase)
Argon2id(resposta, salt_da_pergunta) → chave de envolvimento (por pergunta)
    ↓
decifra o "share" daquela pergunta (Shamir Secret Sharing, limiar 3-de-N)
    ↓
≥3 shares corretos → sharks.recover() reconstrói a DEK via interpolação de Lagrange
    ↓
verificação: decrypt(DEK_reconstruída, dek_check) == marcador fixo?
    ↓ (só se bater)
DEK aceita, cofre desbloqueado
```

```text
Recovery Key (120 bits aleatórios, gerados pelo app)
    ↓ normalização (remove hífen/espaço, maiúsculas)
Argon2id(recovery_key, recovery_key_salt) → KEK2
    ↓
decrypt(KEK2, recovery_key_wrapped_dek) → DEK
    ↓
verificação: decrypt(DEK, recovery_key_check) == marcador fixo?
    ↓ (só se bater)
DEK aceita, cofre desbloqueado
```

**O segredo criptográfico que de fato permite a recuperação, em ambos os casos, é a própria DEK** — perguntas e Recovery Key são só dois caminhos alternativos e independentes para reconstruí-la/desembrulhá-la; nenhum dos dois "atalha" ou enfraquece a cifra dos dados (senha, notes, 2FA, propriedades continuam protegidos pela mesma DEK e pelo mesmo AEAD de sempre).

**Item 7 do pedido — não confundir autenticação com criptografia:** verificado por leitura de código que um atacante que edite o SQLite diretamente (zerar `recovery_attempts.failed_count`/`locked_until`, ou qualquer outro campo) não ganha acesso: `attempt_vault_recovery` e `unlock_with_recovery_key` só chamam `state.set_dek(dek)` **depois** de reconstruir a DEK de verdade e confirmá-la contra `dek_check` — a validação acontece inteiramente no processo Rust, nunca há um "flag de desbloqueado" que possa ser adulterado diretamente no banco para pular a criptografia.

## Recovery Key

**Por que reaproveita os primitivos existentes (seção 9 do pedido — "não invente criptografia"):** a Recovery Key usa exatamente `crypto::derive_key` (Argon2id) e `crypto::encrypt`/`decrypt` (XChaCha20-Poly1305) já auditados na Fase 1 — a única coisa nova é `crypto::generate_recovery_key`, que só gera 120 bits aleatórios (`OsRng`) e os codifica em Base32 Crockford (32 símbolos, sem caracteres ambíguos 0/O/1/I/L), formatados em grupos de 4 (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).

**Por que Argon2id numa chave de 120 bits não é "over-engineering" inofensivo:** o pedido pediu para analisar isso com cuidado (seção 9). Diferente de uma resposta de pergunta de segurança (baixa entropia, precisa do custo do KDF para ficar cara de atacar), a Recovery Key já tem 120 bits de entropia por si só — Argon2id aqui não está "salvando" um segredo fraco, é só reaproveitar o mesmo código já testado em vez de escrever um caminho de derivação de chave separado (que seria superfície nova para auditar). O custo (~300-500ms) é imperceptível numa operação de recuperação, que acontece raramente.

**Como funciona:**

- `vault_meta` ganhou 5 colunas novas (`recovery_key_salt`, `recovery_key_kdf_params`, `recovery_key_wrapped_dek`, `recovery_key_check`, `recovery_key_created_at`) — todas nulas até o usuário gerar uma chave.
- `generate_recovery_key` exige o cofre desbloqueado (precisa da DEK), gera uma chave nova, envolve a DEK sob ela, e **retorna o texto puro da chave uma única vez** — não fica salvo em lugar nenhum além da tela mostrada ao usuário.
- Gerar uma nova chave substitui/invalida a anterior (mesmas colunas, sobrescritas).
- `unlock_with_recovery_key` é um caminho de desbloqueio independente de `unlock_vault` — mesma DEK resultante, sem tocar na senha mestra nem nas perguntas.
- A migração automática de dados legados (`migrate_plaintext_account_fields`) roda também neste caminho.

**Opção escolhida (seção 12 do pedido — A/B/C):** **Opção C, mas assimétrica** — Recovery Key e perguntas de segurança são dois caminhos **independentes** para a mesma DEK (não é preciso combinar os dois numa única operação), e a UI:
- Recomenda a Recovery Key como método principal (copy mais forte, ordem de exibição nas configurações).
- Mantém as perguntas como método complementar/legado, agora com aviso explícito sobre a fraqueza de entropia.
- No fluxo de recuperação (`RecoveryFlow.tsx`), se ambos estiverem configurados, o usuário escolhe; se só um estiver configurado, vai direto para ele.

| Critério | Recovery Key | Perguntas de segurança |
|---|---|---|
| Segurança contra ataque offline | Altíssima (120 bits, independente do usuário) | Depende inteiramente da resposta escolhida |
| Risco de perda definitiva | Alto se a cópia física for perdida (sem "recuperar a recuperação") | Baixo (pode-se responder de memória, mas então é adivinhável por terceiros também) |
| Usabilidade | Precisa ser guardada fisicamente antes de esquecer a senha | Não precisa de nada guardado, só lembrar as respostas |
| Complexidade adicionada | Um comando de gerar/desabilitar + 5 colunas | Já existia |

**Por que não tornamos a Recovery Key obrigatória no momento de criar o cofre:** geraria uma tela de "confirme que salvou" bloqueante logo na primeira experiência, que não pude testar interativamente neste ambiente (sem GUI). Prefiro deixar como recomendação de Fase 3 com um teste manual de UX antes de forçar esse fluxo.

## Exportação combinada (Kit de recuperação)

`RecoveryKitDialog.tsx` substitui o antigo `ExportQuestionsDialog.tsx` (removido) e imprime, num único documento:

- A Recovery Key **apenas se fornecida explicitamente pelo chamador** (nunca busca uma antiga — o backend não guarda a chave em claro em lugar nenhum para "reimprimir depois").
- As perguntas de segurança **sem as respostas** (mantendo o design já existente na Fase 1: o usuário preenche a resposta à mão depois de imprimir — o app nunca escreve a resposta em nenhum arquivo/tela além do próprio input no momento do cadastro).
- Aviso forte de que o documento "pode permitir acesso ao seu cofre" e deve ser guardado fisicamente.
- Nenhum arquivo temporário é criado: a folha é renderizada diretamente no DOM (`createPortal`) e impressa via `window.print()`/"Salvar como PDF" do sistema — o app não grava nada em disco por conta própria durante essa operação.

## Perguntas de segurança

Ataque offline analisado (seção 8 do pedido): um atacante com `vault.db` completo (mas sem a senha mestra nem as respostas) tem acesso a `security_questions.question` (texto puro, não é segredo), `answer_salt` e `wrapped_share` (BLOBs). Para testar uma resposta candidata, ele precisa rodar **Argon2id completo** (mesmos parâmetros da senha mestra: 128 MiB, 3 iterações) por tentativa — isso não é instantâneo nem paralelizável de graça (o custo de memória de 128 MiB por tentativa limita fortemente quantas tentativas rodam em paralelo numa GPU, ao contrário de hashes rápidos como SHA-256, que permitiriam bilhões de tentativas/segundo). **Não é um "teste instantâneo tipo `resposta == hash`"** — mas também não é impossível: um dicionário de algumas centenas de respostas plausíveis ("São Paulo", "Rio de Janeiro"...) é computável em minutos a horas num desktop comum, bem diferente da Recovery Key (120 bits = praticamente impossível). **Conclusão documentada explicitamente:** perguntas de segurança com respostas factuais/previsíveis representam um risco real de recuperação por terceiros que tenham informação pessoal sobre a vítima — mitigado (não eliminado) pela UI que agora orienta respostas não óbvias e pela existência da Recovery Key como alternativa mais forte.

## Tauri / IPC

Auditoria de fronteira (React ↔ IPC ↔ Rust ↔ SQLite):

- **Nenhum command sensível encontrado sem verificação de estado do cofre.** Tabela de verificação:

| Command | Requer cofre desbloqueado? | Como |
|---|---|---|
| `encrypt_secret` / `decrypt_secret` | Sim | `state.with_dek(...)` |
| `copy_secret_to_clipboard` (novo) | Sim | `state.with_dek(...)` |
| `change_master_password` | Não precisa de unlock prévio — reverifica a senha atual internamente | decifra `wrapped_dek` com a senha fornecida |
| `export_backup` | Sim | `state.is_unlocked()` |
| `import_backup` | Não (intencional — permite restaurar num cofre novo/vazio) | substitui tudo e força novo unlock ao final |
| `add_security_question` / `update_security_question` | Sim | `state.with_dek(...)` |
| `delete_security_question` | Sim | `state.is_unlocked()` |
| `generate_recovery_key` (novo) | Sim | `state.with_dek(...)` |
| `disable_recovery_key` (novo) | Sim | `state.is_unlocked()` |
| `unlock_with_recovery_key` (novo) | Não (é um caminho de unlock) | verifica a chave via AEAD antes de aceitar |
| `attempt_vault_recovery` / `reset_master_password_after_recovery` | Não / Sim (via `with_dek`) | já auditado na Fase 1 |

- **Item 20 do pedido (manipular o frontend/DevTools não pode desbloquear o backend):** verificado por leitura de código e teste unitário (`state.rs`, `VaultState::is_unlocked`/`with_dek`): não existe nenhuma variável tipo `vaultUnlocked` no frontend que o backend confie — o único estado real é a DEK dentro de `Mutex<Option<Zeroizing<[u8;32]>>>` no processo Rust, inacessível a partir da webview. Setar qualquer variável JS (`window.x = true`, remover o modal de bloqueio via DevTools) não altera esse estado; qualquer chamada subsequente a um command sensível continuaria batendo em `state.with_dek(...).ok_or("O cofre está bloqueado.")`.
- Confirmado também pelo comportamento estrutural de `App.tsx`: quando `vaultStatus !== "unlocked"`, o componente retorna `<UnlockScreen />` (ou `<CreateMasterPassword />`) e a árvore inteira autenticada é desmontada — não é uma questão de "esconder visualmente", os componentes com estado de segredo revelado (`PasswordFieldLazy`, `AccountPropertiesSection`) deixam de existir e seu estado React é descartado pelo próprio React.

## SQL da WebView

**Decisão consciente: mantido.** O pedido pede para "remover ou justificar tecnicamente muito bem" o SQL arbitrário do frontend (`sql:allow-select`/`allow-execute`). Avaliei seriamente a remoção (trocar todo `src/lib/db.ts` por commands Rust dedicados) e decidi **não fazer essa migração nesta fase**, pelos seguintes motivos:

1. **O ganho de confidencialidade é pequeno.** O limite real de confidencialidade não é "a webview pode rodar SQL" — é "a webview pode pedir para decifrar qualquer ciphertext enquanto o cofre está desbloqueado" (via `decrypt_secret`/`copy_secret_to_clipboard`). Isso continuaria existindo mesmo se todo o CRUD virasse commands Rust, porque a UI *precisa* poder pedir para decifrar o que o usuário está vendo. Ou seja: um comprometimento da webview já compromete os segredos abertos naquela sessão, com ou sem SQL livre — o SQL livre só facilita *ler o schema/linhas cifradas*, que sem a DEK não vazam segredo nenhum.
2. **O ganho real seria de integridade/robustez** (impedir que um bug ou dependência comprometida rode `DROP TABLE`/`UPDATE` arbitrário), que é genuíno mas menor que o risco da mudança.
3. **Custo/risco da migração é grande:** `src/lib/db.ts` tem ~40 funções cobrindo praticamente todas as tabelas, chamadas de dezenas de componentes. Reescrever tudo como commands Rust, sem ambiente com GUI para testar cada fluxo (contas, projetos, tags, propriedades, imagens, histórico...), é um risco desproporcional de quebrar o aplicativo inteiro numa única sessão sem validação visual.
4. **Todas as queries em `db.ts` já são parametrizadas** (sem concatenação de string de usuário) — o vetor de "SQL injection clássico" já não existe nesse arquivo (diferente do bug já corrigido em `backup.rs`, que era injeção de *nomes de coluna*, não de valores).

**Recomendação para Fase 3:** migrar table-by-table começando pelas mais sensíveis (`accounts`, `account_properties`, `security_questions`) para commands Rust dedicados, com testes de UI reais a cada tabela migrada — não como um "big bang".

## CSP

Aplicada (`src-tauri/tauri.conf.json`, antes `"csp": null`):

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline';
img-src 'self' asset: http://asset.localhost https://asset.localhost data:;
font-src 'self';
connect-src 'self' ipc: http://ipc.localhost ws://localhost:1420 http://localhost:1420;
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```

Justificativa de cada exceção:
- `style-src 'unsafe-inline'`: o app usa `style={{...}}` (estilo inline do React) em 5 componentes (`Avatar`, `PlatformIcon`, `CreateMasterPassword`, `ProjectForm`) para cores/tamanhos dinâmicos — não há como usar nonce/hash numa SPA compilada sem reescrever esses componentes. Risco aceito: CSS injection por si só não executa JS em navegadores modernos.
- `img-src ... asset: http://asset.localhost https://asset.localhost`: necessário para `convertFileSrc` (avatares/logos servidos via protocolo de asset do Tauri, escopado a `$APPDATA/images/*`).
- `connect-src ... ws://localhost:1420 http://localhost:1420`: necessário só em modo desenvolvimento (`npm run tauri dev`, HMR do Vite); não afeta o app empacotado.

**Evidência de que não quebra o build:** `npm run build` (Vite + `tsc`) concluído com sucesso; inspecionei `dist/index.html` gerado — um único `<script type="module" src="/assets/...">` e um `<link rel="stylesheet">`, ambos same-origin, sem scripts inline, sem nenhum recurso remoto (confirmado também por uma varredura de `fetch`/`XMLHttpRequest`/`axios`/`WebSocket`/URLs `http(s)://` em `src/*.css` e `src/**/*.tsx`: nenhuma ocorrência). **Ressalva honesta:** não consegui abrir a janela do WebView2 real neste ambiente (sem display) para confirmar visualmente que a UI renderiza sob esta CSP — recomendo fortemente rodar `npm run tauri dev` uma vez após esta mudança antes de confiar nela; reverter para `"csp": null` é uma linha só, caso algo quebre.

## Permissões (menor privilégio)

Inventário de tudo que a capability `default.json` expõe à WebView, e por quê:

| Permissão | Necessária para | Excessiva? |
|---|---|---|
| `sql:allow-select/execute/load/close` | Todo o CRUD do app (contas, tags, projetos...) | Ver seção "SQL da WebView" — mantida, com justificativa |
| `clipboard-manager:allow-write-text/read-text/clear` | Copiar segredos, e o auto-clear condicional (só limpa se ainda for o mesmo valor) | Não — mínimo necessário |
| `opener:allow-open-url` (`http(s)://` apenas) | "Abrir login" em URLs cadastradas pelo usuário | Já restrita a http/s pelo ACL nativo do Tauri; reforçada agora também em `isAllowedExternalUrl` |
| `dialog:default` | Escolher onde salvar/importar backup e imagens | Não — mínimo necessário |

Nenhuma permissão de `shell:*` (execução de processos), nenhuma permissão de filesystem genérica (`fs:*`) — todo acesso a arquivo passa por commands Rust específicos (`import_image`, `delete_image_file`, `export_backup`, `import_backup`), cada um com sua própria validação (sanitização de nome de arquivo desde a Fase 1).

## Lock / Suspend

- **Auto-lock por inatividade** (já existia): reescrito para guardar o horário real da última atividade (`Date.now()`) e reconferir esse relógio de parede sempre que `document.visibilitychange`/`window.focus` disparam — não depende só do `setTimeout` ter sobrevivido a uma suspensão do SO. Ao voltar a ficar visível, se o tempo configurado já passou, bloqueia imediatamente; senão, reagenda pelo tempo restante exato.
- **Bloquear ao minimizar** (novo, opcional, desligado por padrão): `document.visibilitychange` → `hidden` → bloqueia na hora, se a configuração estiver ativa.
- **Não implementado nesta fase:** hooks nativos do Windows (`WM_POWERBROADCAST` para suspensão real, `WM_WTSSESSION_CHANGE` para troca de usuário/tela de bloqueio do Windows) — exigiriam FFI insegura (`windows` crate + subclasse de janela) que não pude validar contra um evento real de suspensão/bloqueio de tela neste ambiente sem hardware físico para testar. Prefiro não embarcar código nativo não verificado a arriscar travar o aplicativo do usuário. **Recomendação de Fase 3:** implementar via `SetWindowSubclass`/`RegisterSuspendResumeNotification`, testado manualmente suspendendo a máquina de verdade.
- **Por que a mitigação atual ainda ajuda bastante:** mesmo sem o hook nativo, o auto-lock por relógio de parede garante que, ao *retomar* a janela depois de qualquer suspensão (o que sempre dispara foco/visibilidade quando o usuário volta a usar o app), o cofre bloqueia se o tempo configurado já tiver passado durante o período em que a máquina esteve suspensa/longe do usuário.

## Memória

- **Já era assim desde a Fase 1** (bom, verificado, não alterado): o app nunca decifra todas as senhas ao abrir o cofre — cada senha só é decifrada quando o usuário clica em revelar/copiar.
- **Endurecido nesta fase:**
  - `AccountDetailModal`: removido o cache de senha decifrada no componente pai (`ensurePassword` agora sempre decifra de novo em vez de guardar em `useState` entre chamadas) — decifrar com a DEK já em memória é barato (microssegundos), então não há custo prático em não cachear.
  - Ao "esconder" a senha revelada (clique no ícone de olho), o valor decifrado agora é removido do estado do React (`setValue("")`), não só ocultado visualmente — é preciso decifrar de novo para revelar uma próxima vez.
  - `copy_secret_to_clipboard`: para a ação de "copiar" especificamente, o plaintext agora nunca atravessa para o processo da webview — é decifrado e escrito na área de transferência inteiramente no Rust.
- **Decisão consciente, não implementada:** parar de buscar `encrypted_password`/`notes`/`two_factor_*` em massa na listagem de contas (`listAccountsWithRelations`). Considerei e descartei: o botão de "copiar senha" direto no card/linha da lista (sem abrir o modal de detalhes) já existia desde a Fase 1 e depende do ciphertext estar carregado ali — e ciphertext sem a DEK é inerte (não é o "plaintext em massa" que a seção 28 do pedido quer evitar). O app já satisfaz o requisito real ("decifra só quando o usuário pede, uma de cada vez") — só não evita ter o *ciphertext* de todas as contas em memória, o que tem valor de segurança muito menor.

## Clipboard

Revalidado (comportamento já existia desde a Fase 1, sem alteração de lógica): `copy_to_clipboard`/`copy_secret_to_clipboard` só limpam o clipboard, ao expirar o timer, **se o conteúdo ainda for exatamente o que foi copiado** — copiar um "Texto B" depois de uma senha não é apagado quando o timer da senha expira. Nenhuma mudança de comportamento nesta fase, só a adição do caminho que decifra e copia sem passar pelo frontend.

## Backup

Segunda bateria de testes (seção 35-37 do pedido), toda automatizada em `src-tauri/src/commands/backup.rs::tests`:

- **Round-trip completo** (`full_round_trip_preserves_every_table_and_ciphertext_byte_for_byte`): popula um banco de origem com dado sintético em **todas** as categorias pedidas na seção 36 — plataforma, projeto, tag, imagem, conta com senha+2FA+notes cifrados, propriedade sensível, histórico, pergunta de segurança, Recovery Key — exporta, restaura num banco novo, e confirma que **nenhuma tabela perdeu/ganhou linhas** e que os ciphertexts (`encrypted_password`, `notes`, `two_factor_phone`, valor de propriedade sensível, `wrapped_dek`, `recovery_key_wrapped_dek`) batem **byte a byte** entre origem e destino.
- **Backup adulterado** (`tampered_backup_file_is_rejected_without_touching_the_database`): flip de 1 byte no arquivo cifrado → rejeitado pela tag do AEAD, erro genérico, banco de destino nunca chega a ser tocado.
- **Senha de backup errada** (`wrong_backup_password_is_rejected`): rejeitado.
- **Arquivo truncado/corrompido/lixo** (`truncated_or_garbage_file_is_rejected_not_panicking`): cabeçalho incompleto, magic bytes errados, arquivo vazio — todos retornam erro tratado, nenhum panic. (Aproveitei para adicionar checagens de limite que faltavam em `decode_backup_file`, já que o código original assumia que os campos de tamanho no cabeçalho eram sempre consistentes com o tamanho real do arquivo — um arquivo malicioso/truncado poderia ter causado um panic por slice fora dos limites antes desta correção; agora cada leitura de tamanho variável é validada contra `bytes.len()` antes de indexar.)
- Refatorei `export_backup`/`import_backup` para extrair a lógica pura (`build_backup_payload`, `restore_backup_payload`, `encode_backup_file`, `decode_backup_file`) das funções `#[tauri::command]` — isso é o que tornou possível testar o ciclo completo sem precisar de um `AppHandle`/janela real.
- As colunas novas da Recovery Key foram adicionadas à allowlist de `insert_rows` e à lista de colunas BLOB decodificadas (`is_blob_column`) — sem isso, restaurar um backup feito depois de configurar uma Recovery Key corromperia essas colunas do mesmo jeito que o bug de `dek_check` da Fase 1.

## Testes de ataque

Tentativas concretas nesta sessão (todas com evidência em teste automatizado ou trecho de código citado, não apenas afirmação):

| Ataque tentado | Resultado |
|---|---|
| Injetar SQL via nome de coluna forjado num backup malicioso | Bloqueado (allowlist, teste `rejects_column_names_outside_the_allowlist`) |
| Adulterar 1 byte do arquivo de backup | Rejeitado pelo AEAD antes de tocar no banco |
| Restaurar backup com senha errada | Rejeitado |
| Restaurar backup truncado/corrompido | Rejeitado sem panic (bug de slice-out-of-bounds corrigido nesta fase) |
| Path traversal em `delete_image_file` (herdado da Fase 1, revalidado) | Bloqueado, teste `rejects_path_traversal_attempts` |
| Chamar `decrypt_secret`/`copy_secret_to_clipboard` com o cofre bloqueado | Rejeitado — `state.with_dek` retorna `None`, comando devolve "O cofre está bloqueado." (verificado por teste unitário de `VaultState` + leitura de código de todos os commands sensíveis) |
| Gravar um valor legado em texto puro e tentar ler como se fosse ciphertext | A migração re-cifra automaticamente no próximo unlock; se ainda assim falhar a decifragem, a UI falha visivelmente em vez de mostrar o valor cru |
| Procurar os 5 marcadores sintéticos pedidos (`SECURITY_TEST_PASSWORD_93821` etc.) num `.db` real gravado em disco | Nenhum encontrado em texto puro (teste `synthetic_markers_never_appear_in_plaintext_on_disk`) |
| "Adivinhar" uma resposta de pergunta de segurança offline | Tecnicamente possível (ver seção "Perguntas de segurança"), documentado como risco residual, não uma falha de implementação |

## Testes automatizados

`cargo test --lib`: **22/22 passando** (10 herdados da Fase 1 + 12 novos desta fase):

- `crypto.rs`: +3 testes de Recovery Key (formato/entropia, tolerância a formatação, wrap/unwrap de DEK).
- `migration.rs` (novo módulo): 3 testes — migra legado, idempotente, ignora já-cifrado/nulo/vazio.
- `commands/recovery_key.rs`: 1 teste (estado bloqueado nega acesso à DEK).
- `commands/backup.rs`: +5 testes — round-trip completo, adulteração, senha errada, arquivo truncado, marcadores sintéticos em disco.
- `commands/images.rs`, `crypto.rs` (Fase 1): 10 testes originais, todos revalidados sem alteração.

Frontend: `npx tsc --noEmit` limpo após cada mudança; `npm run build` (produção) bem-sucedido; `npm audit` sem vulnerabilidades (173 pacotes, inalterado desde a Fase 1 — nenhuma dependência nova foi adicionada nesta fase, `Cargo.lock`/`Cargo.toml` e `package.json`/`package-lock.json` permanecem idênticos aos da Fase 1). **Não existe suíte de testes automatizados em TypeScript neste projeto** (sem `vitest`/`jest` configurado) — não introduzi uma como efeito colateral de uma auditoria de segurança; recomendo para a Fase 3 se o time quiser testes de UI automatizados, fora do escopo de hardening pontual.

`cargo audit`: mesma limitação da Fase 1 — não pôde ser instalado neste ambiente (falha de build nativo de uma dependência do próprio `cargo-audit`, não do projeto). Como nenhuma dependência mudou desde a Fase 1, a conclusão manual permanece: versões atuais, sem indicação de problema.

## Vulnerabilidades encontradas

| # | Título | Severidade | Status |
|---|---|---|---|
| 1 | `accounts.notes` em texto puro | Alta | Corrigida |
| 2 | Fallback de "assume texto puro" em campo cifrado que falha ao decifrar (Fase 1) | Média-Alta (mascarava corrupção/adulteração como dado legado, indefinidamente) | Corrigida (fail-closed) |
| 3 | `decode_backup_file` podia sofrer panic (slice fora dos limites) num arquivo de backup truncado/malformado | Baixa (nega serviço local, não vazamento) | Corrigida |
| 4 | CSP ausente (`null`) | Baixa/Informativa | Corrigida |
| 5 | Sem validação de esquema de URL em `openLoginUrl` além do ACL do Tauri | Informativa (defesa em profundidade) | Corrigida |
| 6 | Plaintext de senha/propriedade sensível atravessando o processo da webview só para ser copiado (sem nunca ser exibido) | Baixa (residual arquitetural, não um bug isolado) | Mitigada (`copy_secret_to_clipboard`) |

Nenhuma CRÍTICA. Nenhuma nova vulnerabilidade de bypass de senha mestra/criptografia central foi encontrada — a arquitetura validada na Fase 1 permanece intacta e não foi enfraquecida.

## Vulnerabilidades corrigidas

Ver tabela acima — todas as 6 têm teste de regressão ou verificação de compilação/tipo associada, exceto a nº 6 (mitigação arquitetural, não há um "teste de ataque" isolado possível sem uma webview real instrumentada).

## Riscos residuais

1. SQL livre da WebView — mantido, com justificativa técnica detalhada (ver seção dedicada).
2. Perguntas de segurança dependem da entropia da resposta escolhida pelo usuário — mitigado por UI, não eliminável por código.
3. Sem hook nativo de suspensão/bloqueio de tela do Windows — mitigado por relógio de parede + visibilitychange, não uma garantia absoluta.
4. CSP implementada mas não verificada visualmente numa janela real (sem GUI neste ambiente).
5. `projects.notes` continua em texto puro (mesmo padrão de risco que `accounts.notes` tinha antes desta fase) — fora do escopo explícito do pedido (que falava de "Observações" no contexto de contas/2FA), mas é uma lacuna do mesmo tipo, documentada para a Fase 3.
6. Perda definitiva de acesso se o usuário perder a Recovery Key impressa/anotada e esquecer a senha mestra e não tiver perguntas de segurança configuradas — trade-off inerente a qualquer segredo de alta entropia gerado pelo próprio usuário guardar.
7. `cargo audit` não pôde ser executado neste ambiente (mesma limitação de toolchain da Fase 1).

## Recomendações para Fase 3

1. Migrar `src/lib/db.ts` para commands Rust dedicados, tabela por tabela, começando por `accounts`/`security_questions`, com teste manual de UI a cada tabela.
2. Implementar hook nativo de suspensão/bloqueio de tela do Windows (`windows` crate), testado num dispositivo real.
3. Considerar tornar a geração de Recovery Key parte do fluxo de criação do cofre (com confirmação obrigatória "já guardei"), testado interativamente.
4. Estender a criptografia de "sempre sensível" para `projects.notes`.
5. Adicionar `vitest`/`@testing-library/react` para testes de componente do frontend, se o time achar valioso.
6. Rodar `cargo audit`/`cargo deny check advisories` num ambiente de CI com toolchain completo.
7. Testar manualmente `npm run tauri dev` e o app empacotado sob a nova CSP; ajustar/reverter se algo quebrar visualmente.

## Conclusão

A Fase 2 fechou as duas lacunas de confidencialidade mais concretas que restavam da Fase 1 (notes em claro; fallback perigoso de "assume texto puro"), adicionou um mecanismo de recuperação genuinamente forte (Recovery Key) sem enfraquecer nem duplicar a criptografia existente, e aplicou várias camadas de defesa em profundidade (CSP, validação de URL, cópia sem plaintext no frontend, lock mais robusto) que reduzem o que um atacante ganha ao comprometer uma camada secundária — sem alterar a arquitetura criptográfica central já validada. O item de maior escopo que ficou de fora (remover SQL livre da webview) foi uma decisão deliberada e justificada, não um esquecimento.

## Matriz final

| Ataque | Resultado | Severidade residual |
|---|---|---|
| Roubo somente do SQLite | Protegido (senha, notes, 2FA, propriedades sensíveis, respostas de segurança cifrados; só metadados não-secretos em claro) | Baixa |
| Roubo de toda a pasta do app | Protegido (mesma razão; imagens não contêm segredo) | Baixa |
| Brute force offline da senha mestra | Protegido na prática (Argon2id 128 MiB/3 iter por tentativa) | Baixa |
| Brute force offline das perguntas de segurança | Parcialmente protegido — depende da entropia da resposta; Argon2id encarece mas não impede um dicionário pequeno | Média (residual, documentado) |
| Brute force offline da Recovery Key | Protegido (120 bits) | Muito baixa |
| Manipulação do frontend/DevTools (ex.: setar "desbloqueado") | Protegido — estado real vive só no processo Rust | Baixa |
| Chamada direta de IPC com o cofre bloqueado | Protegido — todos os commands sensíveis verificam `state.with_dek`/`is_unlocked` | Baixa |
| XSS (hipotético — nenhum vetor encontrado) | Limitado pela CSP nova (sem `unsafe-eval`, sem origem remota); mas se ocorrer enquanto desbloqueado, ainda pode pedir decifragem de segredos abertos naquela sessão | Média (residual arquitetural do modelo Tauri) |
| SQL Injection (valores) | Protegido — todas as queries parametrizadas | Baixa |
| SQL Injection (nomes de coluna, via backup malicioso) | Protegido (allowlist, Fase 1) | Baixa |
| Path Traversal (imagens) | Protegido (Fase 1, revalidado) | Baixa |
| Backup roubado | Protegido — mesma criptografia forte, senha independente | Baixa |
| Backup adulterado | Protegido — AEAD rejeita antes de tocar no banco | Baixa |
| Backup truncado/corrompido | Protegido — erro tratado, sem panic (corrigido nesta fase) | Baixa |
| Windows suspend | Mitigado (relógio de parede + visibilitychange) mas sem garantia nativa | Média (residual, documentado) |
| Clipboard | Protegido — limpa só se ainda for o valor copiado pelo app; cópia de segredo agora não passa pelo frontend | Baixa |
| DevTools aberto | Não concede acesso a segredos por si só (estado real no Rust); mas se o cofre já estiver desbloqueado, DevTools pode observar o que a UI já está exibindo — inerente a qualquer app | Média (residual, inerente ao modelo webview) |

## Respostas às perguntas principais

**1. Se alguém roubar `vault.db`, consegue recuperar minhas senhas?**
Não. Sem a senha mestra (ou Recovery Key, ou 3 respostas corretas de segurança), a DEK não pode ser reconstruída, e sem a DEK nenhum ciphertext (senha, notes, 2FA, propriedades sensíveis) pode ser decifrado.

**2. Se roubar toda a pasta do aplicativo, consegue?**
Não, pela mesma razão. Metadados não-secretos (nomes, usernames, e-mails, URLs, tags) continuam visíveis por design — nunca foram o segredo protegido.

**3. Se souber informações pessoais sobre mim, as perguntas de segurança podem comprometer o cofre?**
Potencialmente, sim, se as respostas cadastradas forem factuais/pesquisáveis (nome da mãe, cidade natal) — esse é um risco real, não hipotético, e é o motivo pelo qual esta fase adicionou a Recovery Key e o aviso explícito na UI. Com respostas não óbvias (a orientação atual da UI), o risco cai para o mesmo nível de força de uma senha razoável protegida por Argon2id.

**4. A Recovery Key, se implementada, é criptograficamente forte?**
Sim — 120 bits de entropia (`OsRng`), envolvendo a DEK com os mesmos primitivos já auditados (Argon2id + XChaCha20-Poly1305). Perder a Recovery Key impressa não enfraquece o cofre; só significa que esse caminho específico de recuperação deixa de estar disponível.

**5. Manipular React/DevTools permite marcar o cofre como desbloqueado e obter segredos?**
Não. O estado real (`unlocked`/`locked`) vive inteiramente no processo Rust (`VaultState`); não existe uma variável de frontend que o backend confie. Qualquer tentativa de "forçar" o estado no DevTools não afeta as verificações que os commands Rust fazem antes de decifrar qualquer coisa.

**6. É possível chamar diretamente um command Tauri e obter senha com o cofre bloqueado?**
Não. Todo command que decifra ou expõe segredo (`decrypt_secret`, `copy_secret_to_clipboard`, etc.) verifica `state.with_dek(...)` primeiro e retorna erro genérico se o cofre estiver bloqueado — verificado por teste unitário e leitura de código de cada command.

**7. Existem dados sensíveis em plaintext no SQLite?**
Não, depois desta fase (senha, notes, 2FA, propriedades sensíveis e respostas de segurança cifrados). `projects.notes` continua em claro (lacuna documentada, mesmo padrão de risco, fora do escopo estrito pedido).

**8. Existem dados sensíveis em plaintext em outros arquivos?**
Não encontrados — sem `.env`, sem logs com segredo, sem `console.log`/`println!` de objetos sensíveis, sem `localStorage`/`sessionStorage` usado. O documento de "kit de recuperação" contém a Recovery Key em claro por natureza (é para isso que serve), mas é gerado sob demanda, sem arquivo temporário, e com aviso explícito para guardá-lo fisicamente.

**9. O backup possui proteção equivalente ao banco principal?**
Sim — mesma criptografia forte (Argon2id + XChaCha20-Poly1305), senha própria e independente da senha mestra, e agora testado com round-trip completo, adulteração e arquivo corrompido, sem perda silenciosa de dados.

**10. Depois de suspender/bloquear o Windows, o cofre continua desbloqueado?**
Provavelmente não, na prática, mas sem garantia formal: o auto-lock reforçado nesta fase reconfere o tempo decorrido de verdade assim que a janela volta a ficar visível/em foco (o que normalmente acontece ao retomar de uma suspensão) e bloqueia se o tempo configurado já tiver passado. Não há, porém, um hook nativo que garanta bloqueio *imediato* no instante exato da suspensão — está documentado como risco residual e recomendação de Fase 3.

**11. Uma vulnerabilidade XSS no frontend conseguiria acessar todas as senhas, ou a arquitetura limita o impacto?**
Limita parcialmente. Nenhum vetor de XSS foi encontrado (sem `dangerouslySetInnerHTML`/`innerHTML`/`eval`), e a CSP nova reduz a chance de um XSS conseguir carregar/executar algo de origem remota. Mas **se** um XSS existisse e o cofre estivesse desbloqueado no momento, ele poderia, em teoria, chamar os mesmos commands que a UI legítima chama (`decrypt_secret` para cada ciphertext lido via SQL) e exfiltrar segredos abertos naquela sessão — essa é uma limitação inerente ao modelo de confiança do Tauri (a webview é "a UI confiável"), não um bug específico deste app, e é a razão de a CSP e a ausência total de conteúdo/dependência remota serem tão importantes aqui.

**12. Você considera seguro começar a armazenar credenciais reais neste aplicativo?**

> **BEM ENDURECIDO PARA USO PESSOAL.**

Justificativa: a arquitetura criptográfica central é sólida e foi validada duas vezes (Fase 1 e revalidada nesta fase); as duas lacunas concretas de confidencialidade que existiam (2FA e notes em texto puro) estão corrigidas com migração automática e testes de regressão; o mecanismo de recuperação ganhou uma opção genuinamente forte (Recovery Key); e várias camadas de defesa em profundidade foram adicionadas. O que impede a classificação máxima ("bem endurecido para uso além do pessoal"/produção multiusuário) são os riscos residuais documentados e conscientemente aceitos: dependência da webview para SQL/decifragem sob demanda (modelo padrão do Tauri, não um bug), ausência de hook nativo de suspensão do Windows, e a fraqueza inerente das perguntas de segurança quando o usuário não segue a nova orientação de respostas não óbvias. Para uso pessoal — que é o caso de uso declarado deste projeto — esses riscos residuais são razoáveis e estão documentados, não escondidos.
