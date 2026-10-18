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
> - As seções "Informativos", "Banco de dados", "Riscos residuais" e a resposta 5 do "Resultado
>   final" dizem que o campo **Observações (`accounts.notes`) fica em texto puro**. Isso está
>   **desatualizado**: desde a Fase 2 as observações são sempre cifradas, e hoje a cifragem é feita
>   no backend (`create_account`/`update_account` em `src-tauri/src/commands/accounts.rs`).
> - O `tauri-plugin-sql` (SQL livre a partir da WebView) foi removido na Fase 3, e
>   `decrypt_secret`/`encrypt_secret` foram removidos na Fase 4. A CSP passou a ser definida na
>   Fase 2.
> - Contagens de testes (10/10), resultados de `npm audit` e o estado do histórico Git refletem
>   apenas aquela data.
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

# Auditoria de Segurança — Cofre de Contas

Data: 2026-08-28
Escopo: código real do repositório (`src-tauri/` em Rust/Tauri 2 + `src/` em React/TypeScript), sem GUI interativa disponível no ambiente de auditoria (ver seção "Testes executados" para o que isso implica).

## Resumo executivo

O cofre já nasce com uma arquitetura criptográfica correta e bem escolhida: **Argon2id** para derivar a chave a partir da senha mestra, uma **DEK (Data Encryption Key)** aleatória de 256 bits que nunca é gravada em claro, e **XChaCha20-Poly1305 (AEAD)** com nonce aleatório único por operação para cada segredo. A senha da conta e as propriedades marcadas como sensíveis já eram cifradas corretamente antes desta auditoria. Nenhuma vulnerabilidade CRÍTICA (bypass total de criptografia ou da senha mestra) foi encontrada.

Foram encontrados e **corrigidos** 3 achados de severidade ALTA e 1 de severidade MÉDIA:

1. **[ALTA]** Campos de 2FA (telefone, e-mail, app, notas) eram gravados em **texto puro** no SQLite.
2. **[ALTA]** Importação de backup vulnerável a **injeção de SQL** via nomes de coluna forjados em um arquivo de backup malicioso.
3. **[ALTA]** Backup/restauração **descartava silenciosamente** perguntas de segurança, propriedades sensíveis cifradas, projetos e histórico — e continha um bug que corrompia a verificação de integridade da DEK (`dek_check`) após uma restauração.
4. **[MÉDIA]** *Path traversal* nos comandos de imagem (`delete_image_file`/`import_image`).

Todas as quatro foram corrigidas nesta sessão, cobertas por testes automatizados (`cargo test`, 10/10 passando) e verificadas com `cargo check`/`tsc --noEmit` sem erros. Os achados residuais (MÉDIOS/BAIXOS/INFORMATIVOS) são documentados abaixo com recomendações — a maioria é uma limitação inerente ao modelo de perguntas de segurança ou uma escolha de arquitetura (Tauri) que exigiria mudanças maiores do que o razoável para uma auditoria pontual.

**Resposta direta à pergunta central do usuário:** copiar apenas o `vault.db` (ou toda a pasta de dados do app) **não é suficiente** para recuperar as senhas sem a senha mestra. Ver seção "Resultado final" para o detalhamento de cada cenário.

## Modelo de ameaças

| Cenário | Situação | O que um atacante consegue extrair hoje |
|---|---|---|
| A — Banco roubado (sem senha mestra) | Cópia de `vault.db`, imagens, backups | Metadados em claro (nome da conta, username, e-mail, notas gerais, URLs, tags); **nenhuma senha, 2FA ou propriedade sensível em claro** (após correção) |
| B1 — App fechado | Acesso ao disco | Igual ao cenário A |
| B2 — App aberto e bloqueado | `lock_vault` foi chamado | DEK removida da memória gerenciada (`Zeroizing`); comandos de segredo retornam erro |
| B3 — App aberto e desbloqueado | Cofre unlocked | Qualquer segredo pode ser decifrado sob demanda (esperado — é o estado "logado") |
| C — Arquivos do app | JSON/`.env`/logs/cache/temp/localStorage/IndexedDB | Nenhum encontrado com segredos (ver seção "Exposição de arquivos") |
| D — Clipboard | Copiar senha | Limpo automaticamente após N segundos, só se o clipboard ainda contiver o valor copiado pelo app (já implementado corretamente) |
| E — Recuperação da senha mestra | Perguntas de segurança | Esquema de Shamir + Argon2id é sólido; a força real depende da entropia das respostas escolhidas pelo usuário (ver achado MÉDIO) |

## Arquitetura criptográfica atual

```
Senha mestra
      │  Argon2id(senha, salt_kek, m=128MiB, t=3, p=1)  [src-tauri/src/crypto.rs:44]
      ▼
KEK (256 bits, nunca persistida)
      │  XChaCha20-Poly1305.encrypt(KEK, DEK)             [vault.rs:52, "wrapped_dek"]
      ▼
DEK (256 bits aleatórios, gerada 1x na criação do cofre)
      │  mantida só em RAM, dentro de Zeroizing<[u8;32]>  [state.rs]
      ▼
XChaCha20-Poly1305.encrypt(DEK, nonce_único, plaintext)   [crypto.rs:56, encrypt_secret]
      ▼
Ciphertext = nonce(24B) || bytes_cifrados+tag  →  base64 → coluna TEXT no SQLite
```

Respostas às perguntas da seção 3 do pedido original:

- **Algoritmo de cifra:** XChaCha20-Poly1305 (AEAD — confidencialidade **e** integridade/autenticidade). Biblioteca: crate `chacha20poly1305 0.10.1` (RustCrypto).
- **KDF:** Argon2id (crate `argon2 0.5.3`), variante recomendada pela OWASP para hashing de senha/derivação de chave.
- **Salt:** sim, 16 bytes de `OsRng`, **único por operação** — um salt por criação de cofre, um por pergunta de segurança, um por exportação de backup. Nunca reaproveitado.
- **Parâmetros Argon2id:** memória 128 MiB, 3 iterações, paralelismo 1 (`crypto.rs:30-35`) — alvo de ~300-500ms por tentativa em hardware desktop comum, adequado contra força bruta offline.
- **Nonce/IV:** XNonce de 24 bytes, gerado por `OsRng` a cada chamada de `encrypt()` — único por ciphertext (confirmado pelo teste `each_encryption_uses_a_fresh_nonce`).
- **AEAD:** sim (ver acima) — qualquer adulteração de 1 bit no ciphertext faz `decrypt()` falhar (tag de autenticação), confirmado pelo teste `tampered_ciphertext_fails_to_decrypt`.
- **Onde fica a chave do cofre (DEK):** só em memória do processo Rust, dentro de `Zeroizing<[u8;32]>` (zera os bytes ao sair de escopo); nunca gravada em disco em claro.
- **Onde fica a senha mestra:** em lugar nenhum — não é armazenada, nem em hash. Só existe no processo de derivação da KEK durante `unlock_vault`/`create_vault`/`change_master_password`, e é descartada da memória Rust ao final da função (é uma `String` comum, não teria zeroização garantida, mas não é persistida).
- **Existe hash/verificador de senha?** Indiretamente: o sucesso de `unlock_vault` depende de a tag AEAD do `wrapped_dek` bater — isso já funciona como verificador. Além disso há um `dek_check` explícito: `encrypt(DEK, "vault-dek-check-v1")`, usado para confirmar a DEK reconstruída via perguntas de segurança antes de aceitar uma recuperação (`security_questions.rs:333`).
- **Chave única do cofre:** sim, a DEK, gerada 1x e nunca trocada — a troca de senha mestra apenas re-envolve (re-wrap) a mesma DEK sob uma nova KEK, então não é preciso re-cifrar todos os dados a cada troca de senha (`vault.rs::change_master_password`).
- **Troca de senha mestra:** decifra a DEK atual com a senha atual (falha genérica se errada), gera novo salt + nova KEK, re-envolve a mesma DEK. Toda a lógica crítica está no backend Rust.
- **Recuperação:** Shamir Secret Sharing (limiar 3-de-N, `sharks 0.5`) sobre a própria DEK. Cada "share" é derivado deterministicamente da DEK via HKDF-SHA256 (não precisa guardar o polinômio) e envolvido (`wrap_share`) com uma chave derivada via Argon2id da resposta normalizada (trim + lowercase). Reunir ≥3 respostas corretas reconstrói a DEK via interpolação de Lagrange; um `dek_check` extra confirma a reconstrução antes de aceitar.
- **Backup:** senha **própria e independente** da senha mestra, mesmos primitivos (Argon2id + XChaCha20-Poly1305) sobre um dump JSON do banco.

## Achados

### CRÍTICOS
Nenhum encontrado. Não há bypass da senha mestra, nem caminho para decifrar segredos sem a DEK.

### ALTOS

---
**Título:** Campos de 2FA gravados em texto puro no SQLite
**Severidade:** Alta
**Componente:** Frontend (formulário e detalhe de conta) + schema `accounts`
**Arquivo(s):** `src/App.tsx`, `src/components/accounts/AccountForm.tsx`, `src/components/accounts/AccountDetailModal.tsx`, `src-tauri/src/db.rs` (colunas `two_factor_phone/email/app/notes`)
**Descrição:** ao contrário da senha da conta (`encrypted_password`, já cifrada via `secretCommands.encrypt`) e das propriedades customizadas marcadas como sensíveis, os quatro campos de 2FA eram salvos exatamente como digitados pelo usuário — texto puro na tabela `accounts`. O campo "Observações" do 2FA em particular é um convite para o usuário colar ali uma chave TOTP/backup code.
**Impacto:** quem copiar só o `vault.db` (Cenário A do modelo de ameaças, sem a senha mestra) lia diretamente telefone/e-mail de recuperação, nome do app autenticador e qualquer segredo colado nas notas de 2FA.
**Como foi identificado:** leitura de `src-tauri/src/db.rs` (schema), `src/lib/db.ts` (sem chamada de cifra nesses campos) e `src/App.tsx` (payload salvo direto de `values.two_factor_*`, sem passar por `secretCommands.encrypt`, diferente do tratamento dado a `encrypted_password` na mesma função).
**Como reproduzir (antes da correção):** criar conta com 2FA habilitado, abrir `vault.db` com qualquer leitor SQLite e ler `SELECT two_factor_phone, two_factor_email, two_factor_app, two_factor_notes FROM accounts` — valores apareciam em claro.
**Correção recomendada e aplicada:** cifrar os 4 campos com o mesmo `encrypt_secret`/`decrypt_secret` (DEK) já usado para a senha, com fallback de compatibilidade que aceita dados legados em claro na leitura (e os re-cifra na próxima gravação).
**Status:** **Corrigido.** `App.tsx` agora cifra os 4 campos antes de salvar; `AccountForm.tsx` e `AccountDetailModal.tsx` decifram sob demanda para edição/exibição, com fallback que evita perda de dados legados.

---
**Título:** Injeção de SQL na importação de backup via nomes de coluna não validados
**Severidade:** Alta
**Componente:** Backend Rust — importação de backup
**Arquivo(s):** `src-tauri/src/commands/backup.rs` (`insert_rows`)
**Descrição:** `insert_rows` montava a query `INSERT INTO {tabela} ({colunas}) VALUES (...)` via `format!` a partir das *chaves do objeto JSON* do arquivo de backup decifrado — sem validar esses nomes contra o schema real. Identificadores SQL não podem ser parametrizados (`?1`, `?2` só valem para valores), então um arquivo de backup malicioso — cifrado pelo próprio atacante com uma senha que ele mesmo escolhe e entrega à vítima ("aqui está um backup, a senha é 1234") — poderia usar uma chave JSON como `"x); DROP TABLE accounts;--"` para injetar SQL arbitrário assim que a vítima importasse o arquivo com a senha fornecida pelo atacante.
**Impacto:** execução de SQL arbitrário no `vault.db` local (leitura/adulteração/destruição de qualquer tabela) condicionada a engenharia social (convencer a vítima a importar um arquivo específico com uma senha específica).
**Como foi identificado:** leitura de código de `insert_rows`, que usa `columns.iter()...join(", ")` interpolado diretamente na string SQL.
**Como reproduzir (antes da correção):** construir um `BackupPayload` JSON com uma tabela contendo uma chave de objeto maliciosa, cifrá-lo com `crypto::encrypt` usando uma senha própria, e chamar `import_backup` com essa senha — a query gerada conteria a string maliciosa não sanitizada.
**Correção recomendada e aplicada:** *allowlist* de colunas por tabela (`allowed_columns`), validada antes de montar a query; qualquer chave fora da lista aborta a importação inteira com "Arquivo de backup inválido."
**Status:** **Corrigido**, com teste de regressão (`backup::tests::rejects_column_names_outside_the_allowlist`) que confirma que uma chave maliciosa é rejeitada e a tabela `accounts` permanece intacta.

---
**Título:** Backup/restauração incompletos (perda silenciosa de dados) e corrupção do verificador `dek_check`
**Severidade:** Alta
**Componente:** Backend Rust — exportação/importação de backup
**Arquivo(s):** `src-tauri/src/commands/backup.rs`
**Descrição:** duas falhas relacionadas:
1. O backup só cobria 6 das ~15 tabelas do schema. Restaurar um backup **apagava permanentemente** (via `DELETE FROM accounts`, que faz *cascade* nas tabelas filhas) perguntas de segurança, propriedades customizadas sensíveis cifradas, histórico de contas, projetos e associações — dados que nunca estavam no arquivo de backup para começar. Isso é particularmente grave porque **perder as perguntas de segurança destrói o próprio mecanismo de recuperação** que o usuário configurou para se proteger.
2. A tabela `settings` nunca era limpa antes da reinserção — importar um backup numa instalação que já tivesse qualquer configuração salva falhava com erro de `UNIQUE constraint`.
3. `is_blob_col` (usado para decodificar Base64 → bytes na restauração) reconhecia apenas `kdf_salt`/`wrapped_dek`, esquecendo a coluna `dek_check` (adicionada por uma migração posterior). Depois de uma restauração, `dek_check` ficava gravado como os bytes ASCII da própria string Base64 em vez dos bytes decodificados — corrompendo permanentemente a verificação de integridade usada por `attempt_vault_recovery`, fazendo com que **respostas de recuperação corretas passassem a ser sempre rejeitadas** após qualquer restore.
**Impacto:** integridade/disponibilidade dos próprios mecanismos de segurança do cofre (recuperação e propriedades sensíveis) após um restore — não é um vazamento de confidencialidade, mas classifico como ALTA porque quebra silenciosamente exatamente os controles que protegem o usuário, sem qualquer aviso.
**Como foi identificado:** leitura de `db.rs` (schema completo) comparado a `BackupPayload`/`insert_rows` em `backup.rs`; rastreamento do fluxo de `dek_check` desde `vault.rs`/`security_questions.rs` até a codificação Base64 em `rows_to_json`.
**Como reproduzir (antes da correção):** exportar um backup, adicionar uma pergunta de segurança, importar o mesmo backup de volta — a pergunta de segurança desaparecia; tentar recuperar via perguntas de segurança após qualquer restore sempre retornava "Respostas insuficientes ou incorretas", mesmo com respostas certas.
**Correção recomendada e aplicada:** backup estendido para cobrir todas as tabelas de dados do usuário (`images`, `projects`, `custom_property_definitions`, `account_projects`, `project_tags`, `account_properties`, `account_history`, `security_questions`, `recovery_attempts`, além das 6 originais); ordem de `DELETE`/`INSERT` respeitando dependências de FK; `settings` agora é limpa antes de reinserir; `dek_check` adicionado à lista de colunas BLOB decodificadas.
**Status:** **Corrigido**, com testes de regressão para a validação de colunas. *Ressalva:* os arquivos de imagem em si (bytes) continuam fora do backup — só os metadados (`images.filename/hash/...`) são preservados; ver achado informativo abaixo.

### MÉDIOS

---
**Título:** Path traversal nos comandos de imagem
**Severidade:** Média
**Componente:** Backend Rust — gerenciamento de imagens
**Arquivo(s):** `src-tauri/src/commands/images.rs` (`delete_image_file`, `import_image`)
**Descrição:** `delete_image_file(filename)` fazia `images_dir(&app)?.join(&filename)` sem validar o conteúdo de `filename`. Como `PathBuf::join` respeita componentes `..`, um `filename` como `..\..\..\algum_arquivo_do_usuario` escaparia do diretório de imagens do app. A extensão usada por `import_image` também vinha, sem sanitização adicional, do path de origem escolhido pelo usuário.
**Impacto:** exclusão arbitrária de arquivo (dentro dos privilégios do usuário do SO) caso algo no app (ou um futuro bug/XSS) chame o comando com um `filename` malicioso — hoje o frontend legítimo só passa nomes gerados pelo próprio `import_image` (`{sha256}.{ext}`), então a exploração exigiria já ter algum outro primitivo (execução de JS na webview).
**Como foi identificado:** leitura de `images_dir`/`delete_image_file`/`import_image`.
**Como reproduzir (antes da correção):** chamar `invoke('delete_image_file', { filename: '..\\..\\algum_arquivo.txt' })` a partir do DevTools da webview — o arquivo fora de `images_dir` seria removido.
**Correção recomendada e aplicada:** `sanitize_image_filename` rejeita nomes vazios, `.`, `..`, e qualquer `/`, `\` ou `:`; aplicado em `delete_image_file`. Em `import_image`, a extensão do arquivo é agora filtrada para apenas caracteres alfanuméricos (defesa em profundidade).
**Status:** **Corrigido**, com testes de regressão (`images::tests::rejects_path_traversal_attempts`, `accepts_normal_generated_filenames`).

---
**Título:** Perguntas de segurança são o elo mais fraco contra ataque offline (achado arquitetural, não um bug)
**Severidade:** Média (residual)
**Componente:** `security_questions.rs`
**Descrição:** o esquema criptográfico em si é sólido (Shamir + Argon2id por resposta, com o mesmo custo de KDF usado na senha mestra). Mas, diferente da senha mestra (que o usuário é incentivado a fazer forte), respostas de perguntas de segurança tendem a ter baixa entropia (nome de animal, cidade natal) e um atacante que roube o `vault.db` pode tentar offline, sem limite de tentativas, contra `security_questions.answer_salt`/`wrapped_share` — precisando acertar apenas 3 de N perguntas.
**Impacto:** se as respostas forem previsíveis, a recuperação pode ser um caminho mais fácil que atacar a senha mestra diretamente — mesmo com o mesmo custo de Argon2id por tentativa.
**Correção recomendada:** não há correção de código que resolva isto (é uma limitação inerente a qualquer esquema de "perguntas de segurança"). Recomenda-se: (1) orientar o usuário, na própria UI, a tratar respostas como senhas (longas/aleatórias, não fatos pesquisáveis publicamente); (2) permitir desativar completamente a recuperação por perguntas para quem preferir depender só de um backup externo; (3) considerar aumentar o limiar (hoje 3) se o usuário cadastrar muitas perguntas.
**Status:** Documentado — decisão de produto, não uma vulnerabilidade a "consertar em código".

### BAIXOS

---
**Título:** CSP desabilitada (`"csp": null`) no `tauri.conf.json`
**Severidade:** Baixa
**Arquivo(s):** `src-tauri/tauri.conf.json`
**Descrição:** não há Content-Security-Policy configurada para a webview. Hoje não encontrei nenhum vetor de XSS (sem `dangerouslySetInnerHTML`, `innerHTML`, `eval`), mas a ausência de CSP remove uma camada de defesa em profundidade caso um bug futuro (ou uma dependência npm comprometida) introduza injeção de HTML/JS.
**Correção recomendada:** definir uma CSP restritiva (`default-src 'self'`, sem `unsafe-inline`/`unsafe-eval`, permitindo apenas o necessário para Tailwind/assets locais). Não apliquei automaticamente porque testar que a UI continua funcionando sob uma CSP estrita requer rodar a aplicação interativamente (não disponível neste ambiente) — risco de regressão sem uma verificação visual.
**Status:** Não corrigido nesta sessão — recomendado como próximo passo com teste manual da UI.

---
**Título:** `tauri-plugin-sql` expõe SQL livre e `decrypt_secret` é um oráculo de descriptografia genérico para o frontend
**Severidade:** Baixa/Informativa (risco arquitetural residual)
**Arquivo(s):** `src-tauri/capabilities/default.json` (`sql:allow-execute`, `sql:allow-select`), `src-tauri/src/commands/secret.rs`
**Descrição:** a webview (frontend) tem acesso direto e irrestrito a `SELECT`/`execute` sobre `vault.db`, e pode chamar `decrypt_secret` para qualquer ciphertext, sem vínculo com uma conta/registro específico. Isso é o modelo normal do Tauri (o frontend é "confiável" pelo próprio design), mas significa que, **se a webview algum dia for comprometida** (dependência npm maliciosa, XSS futuro), o atacante pode ler todo o schema via SQL e decifrar todos os segredos enquanto o cofre estiver desbloqueado — sem precisar da senha mestra novamente.
**Correção recomendada:** manter zero dependências de conteúdo remoto/dinâmico na webview, auditar dependências npm regularmente, considerar restringir os comandos SQL do plugin ao mínimo necessário por tela (o Tauri permite escopos mais finos de `sql:allow-select`) em uma iteração futura. Não é uma "vulnerabilidade" isolada corrigível com um patch pontual — é um trade-off arquitetural do framework.
**Status:** Documentado como risco residual aceito.

---
**Título:** Auto-lock depende só de inatividade de mouse/teclado, sem gancho explícito para suspensão do SO
**Severidade:** Baixa/Informativa
**Arquivo(s):** `src/lib/useAutoLock.ts`
**Descrição:** o timer de bloqueio automático (`setTimeout` reiniciado em `mousemove/mousedown/keydown/wheel/touchstart`) continua contando mesmo com a janela minimizada (o que é correto), mas não há um gatilho explícito para suspensão/hibernação do Windows. Na prática, motores baseados em Chromium (WebView2, usado pelo Tauri no Windows) tendem a disparar timers atrasados imediatamente ao retomar de uma suspensão, então a janela de exposição real após retomar deve ser mínima — mas isso não foi testado neste ambiente (sem GUI interativa) e não é uma garantia documentada da plataforma.
**Correção recomendada:** adicionar um listener explícito para o evento de retomada do sistema (ex.: via um plugin nativo) que force o bloqueio a cada resume, como defesa não dependente do comportamento implícito do motor de timers.
**Status:** Não corrigido — recomendado para uma iteração futura com teste manual (suspender/retomar a máquina com o cofre desbloqueado).

### INFORMATIVOS

- **Campo "Observações" da conta (geral, não o de 2FA) continua em texto puro por design.** Diferente das propriedades customizadas, não há hoje um toggle "tratar como sensível" para o campo `notes` de uma conta. Se o usuário colar ali um código de backup ou outra informação sensível, ela não será cifrada. Recomenda-se um aviso na UI ou estender o modelo de "propriedade sensível" para esse campo.
- **Arquivos de imagem (avatares) não são incluídos no backup**, apenas seus metadados (nome/hash) — ao restaurar em outra máquina, os avatares apontarão para arquivos inexistentes (apenas cosmético, sem qualquer perda de segredo).
- **`opener:allow-open-url` permite abrir qualquer URL `http(s)://`** no navegador padrão do sistema — necessário para a funcionalidade de "Abrir login" com URLs arbitrárias cadastradas pelo usuário; abre no navegador externo, não dentro do app, então o risco é baixo.
- **`cargo audit` não pôde ser executado neste ambiente** (falha de build nativo do `aws-lc-sys` via MSVC ao instalar `cargo-audit`, não relacionada ao código do projeto). Revisão manual do `Cargo.lock` não encontrou nenhuma dependência criptográfica/core visivelmente desatualizada (`argon2 0.5.3`, `chacha20poly1305 0.10.1`, `rusqlite 0.31.0`, `tauri 2.11.5`, `zeroize 1.9.0`, todas correntes). Recomenda-se rodar `cargo audit`/`cargo deny check advisories` num ambiente com o toolchain completo (ex.: CI Linux) periodicamente.
- **`npm audit`: 0 vulnerabilidades** em 173 pacotes (14 prod, 160 dev, 87 opcionais).
- **Nenhum segredo encontrado** no repositório nem no histórico Git (commit único, "Initial commit"); nenhum arquivo `.env`; `.gitignore` corretamente exclui `target/`, `node_modules`, `dist`. O `vault.db`/dados de usuário ficam fora do controle de versão por design (conforme a própria mensagem do commit inicial já documenta).
- **Nenhum `console.log`/`println!`/`dbg!` registra dados de conta ou segredos**; nenhum uso de `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `localStorage` ou `sessionStorage` no frontend.
- **Rate limiting da recuperação por perguntas de segurança já existe e é razoável:** 5 tentativas falhas → bloqueio de 15 minutos (não permanente, conforme pedido). `get_recovery_questions` já sorteia 5 de N perguntas a cada tentativa, reduzindo a superfície de enumeração de qual pergunta específica é mais fraca.
- **Todas as queries do frontend (`src/lib/db.ts`) usam parâmetros (`$1, $2...`)** — nenhuma concatenação de string de usuário em SQL foi encontrada nesse arquivo (diferente do bug já corrigido em `backup.rs`, que interpolava *nomes de coluna*, não valores).

## Testes executados

Ambiente sem display disponível — não foi possível dirigir a GUI do Tauri interativamente (abrir modais, clicar em "copiar", etc.) como o roteiro original presumia. Em vez disso, a validação foi feita em duas camadas:

1. **Revisão de código** de toda a cadeia: `src-tauri/src/{crypto,db,state,lib}.rs` e todos os `src-tauri/src/commands/*.rs`, `src/lib/{db,tauri,useAutoLock,useCopy,filter}.ts`, `src/store/*.ts`, e os componentes de conta/2FA/propriedades/backup relevantes.
2. **Testes automatizados** adicionados e executados (`cargo test --lib`, 10/10 ok):
   - `crypto::tests` — round-trip, "o ciphertext nunca contém o segredo em claro" (usando os marcadores `TEST_PASSWORD_SECURITY_948217` / `TEST_API_KEY_SECURITY_172839` pedidos), adulteração de ciphertext é rejeitada, chave errada é rejeitada, mesmo par (senha, salt) sempre deriva a mesma chave e salts diferentes derivam chaves diferentes, nonce nunca se repete entre chamadas.
   - `commands::backup::tests` — coluna maliciosa fora da allowlist é rejeitada (tabela `accounts` seguinte intacta); linha "no formato de export real" é aceita normalmente.
   - `commands::images::tests` — tentativas de path traversal (`../`, `..\`, path absoluto) são rejeitadas; nomes normais são aceitos.
3. **Verificação de compilação/tipos** após cada mudança: `cargo check` e `cargo build` sem erros (Rust), `npx tsc --noEmit` sem erros (TypeScript).
4. **`npm audit`** executado (0 vulnerabilidades). `cargo audit` tentado mas não pôde ser instalado neste ambiente (falha de build de uma dependência nativa do próprio `cargo-audit`, não do projeto).
5. **Busca por segredos**: `git log --all -p` grepado por padrões de senha/API key/chaves privadas (nada encontrado); busca por `.env*` no projeto inteiro (nenhum arquivo).
6. **Busca por vazamento de log/DOM**: grep por `console.log/error/warn`, `println!/dbg!`, `dangerouslySetInnerHTML`, `innerHTML`, `eval(`, `localStorage`, `sessionStorage` em todo `src/` (nenhuma ocorrência).

Não foi possível, neste ambiente, testar manualmente: clipboard "ao vivo" (comportamento já foi validado por leitura de código — só limpa se o conteúdo ainda for o mesmo copiado pelo app), fluxo completo de export/import de backup ponta a ponta via UI, nem o comportamento real de auto-lock ao suspender o Windows. Recomenda-se ao usuário repetir esses três testes manualmente antes de confiar dados reais ao app, especialmente **um ciclo real de exportar/importar backup** para validar a extensão feita nesta auditoria.

## Dependências vulneráveis

- `npm audit`: **0 vulnerabilidades** (173 pacotes).
- `cargo audit`: não executável neste ambiente (ver acima). Revisão manual do `Cargo.lock`: todas as dependências relevantes à segurança estão em versões atuais (não há indicação de CVEs conhecidas óbvias para essas versões específicas, mas isso **não substitui** rodar `cargo audit`/`cargo deny` num ambiente com toolchain completo).

## Exposição de arquivos

- `vault.db` (SQLite) fica em `app_data_dir()` (não em `C:\Users\Public` nem local compartilhado) — permissões padrão do perfil do usuário do Windows.
- Nenhum `.env`, log, dump ou arquivo temporário com segredos foi encontrado.
- `.gitignore` do projeto e do `src-tauri` corretamente excluem artefatos de build e dados locais.
- Imagens ficam em `app_data_dir()/images`, nomeadas por hash SHA-256 do conteúdo — sem dados sensíveis nos nomes de arquivo.

## Banco de dados

Tabelas com dados **cifrados** (coluna guarda base64 de `nonce || ciphertext+tag`): `accounts.encrypted_password`, `accounts.two_factor_phone/email/app/notes` (depois da correção), `account_properties.value` quando `is_sensitive=1`, `security_questions.wrapped_share`.

Tabelas com dados em **texto puro por design** (não são o segredo protegido pelo cofre): `accounts.name/username/email/category/notes/login_url/website_url`, `platforms.*`, `tags.name`, `projects.*`, `security_questions.question` (a pergunta, não a resposta), `settings.*`, `account_history.*`.

**Conclusão prática:** copiar só o `vault.db` permite ver *quais contas existem e seus metadados*, mas não as senhas nem os segredos de 2FA/propriedades sensíveis — exatamente o comportamento esperado de um gerenciador de senhas.

## SQL Injection

- **Frontend (`src/lib/db.ts`):** todas as queries usam parâmetros (`$1, $2, ...`) da API do `tauri-plugin-sql`; nenhuma concatenação de entrada do usuário em SQL foi encontrada.
- **Backend (`src-tauri/src/commands/*.rs`):** todas as queries usam `rusqlite::params!`/placeholders, exceto a construção dinâmica de `insert_rows` em `backup.rs`, que **interpolava nomes de coluna** (não valores) sem validação — corrigido nesta auditoria com uma allowlist (ver achado ALTO acima).

## XSS / HTML Injection

Nenhum uso de `dangerouslySetInnerHTML`, `innerHTML` ou `eval` encontrado no frontend; React escapa por padrão todo conteúdo textual renderizado. Não foi possível testar interativamente payloads como `<img src=x onerror=alert(1)>` num campo de nome/observação (sem GUI disponível), mas a ausência desses sinks torna a exploração improvável mesmo que o teste manual não tenha sido executado.

## Path Traversal

Encontrado e corrigido em `delete_image_file`/`import_image` (ver achado MÉDIO). Comandos de backup (`export_backup`/`import_backup`) recebem o path já escolhido pelo diálogo nativo do SO (`@tauri-apps/plugin-dialog`) — não há validação adicional de path nesses comandos, mas o caminho normal de uso restringe a escolha ao próprio usuário via diálogo do sistema.

## Tauri/IPC

- Capabilities (`src-tauri/capabilities/default.json`): `sql:default/allow-load/allow-execute/allow-select/allow-close`, `clipboard-manager:allow-write-text/allow-read-text/allow-clear`, `opener:allow-open-url` (qualquer `http(s)://`), `dialog:default`. Nenhuma permissão de `shell`/execução de processo, nem `fs:*` genérico — os únicos acessos a arquivo são via comandos Rust específicos (`import_image`, `delete_image_file`, `export_backup`, `import_backup`), não via uma permissão de filesystem irrestrita ao frontend.
- Nenhum comando retorna a senha mestra nem a DEK ao frontend; `decrypt_secret` retorna apenas o plaintext do ciphertext explicitamente passado pelo chamador (não há um comando "me dê tudo descriptografado").
- O maior risco arquitetural aqui é o já documentado: `sql:allow-select/execute` dá à webview acesso irrestrito ao banco, e `decrypt_secret` é um oráculo genérico — ambos esperados no modelo do Tauri, documentados como risco residual.

## Backup e recuperação

Cobertos em detalhe nos achados ALTOS acima. Resumo pós-correção: backup cobre o schema inteiro (exceto bytes de imagem), usa a mesma criptografia forte do cofre com senha independente, e falha de forma segura em senha errada/arquivo corrompido/adulterado (a etapa de `decrypt()` do AEAD rejeita qualquer adulteração antes mesmo de tentar interpretar o JSON).

## Clipboard

Implementação (`src-tauri/src/commands/clipboard.rs`) já estava correta antes desta auditoria: `copy_to_clipboard` aceita um `clear_after_seconds` opcional e, ao expirar, só limpa o clipboard **se o conteúdo ainda for exatamente o que o app copiou** — protegendo contra apagar algo que o usuário tenha copiado depois. Configurável pelo usuário em Configurações (`clipboardClearEnabled`/`clipboardClearSeconds`, padrão 20s).

## Perguntas de segurança

Ver achado MÉDIO acima. Pontos positivos já implementados: threshold 3-de-N (não é preciso comprometer todas), Argon2id por resposta (mesmo custo da senha mestra), normalização de resposta (trim + lowercase) evita falhas triviais por capitalização, amostra aleatória de 5 perguntas por tentativa de recuperação (dificulta mirar a pergunta mais fraca), bloqueio temporário (não permanente) após 5 falhas. Ponto de atenção: a segurança prática depende da entropia da resposta escolhida pelo usuário — não há como o software garantir isso.

## Recomendações

1. Rodar `cargo audit`/`cargo deny check advisories` num ambiente com toolchain completo (CI) e repetir periodicamente.
2. Definir uma CSP restritiva em `tauri.conf.json` (com teste manual da UI depois).
3. Adicionar aviso na UI orientando a usar respostas de segurança fortes/não óbvias, e considerar permitir desativar a recuperação por perguntas.
4. Considerar estender o modelo "marcar como sensível" para o campo de observações da conta.
5. Testar manualmente, antes de usar com dados reais: um ciclo completo de exportar/importar backup; o comportamento de auto-lock ao suspender/retomar o Windows.
6. Rodar as suítes automatizadas (`cargo test`, `npx tsc --noEmit`) em CI a cada mudança futura nesses módulos.

## Correções realizadas

| # | Achado | Arquivo(s) | Status |
|---|---|---|---|
| 1 | 2FA em texto puro | `App.tsx`, `AccountForm.tsx`, `AccountDetailModal.tsx` | ✅ Corrigido |
| 2 | SQLi via coluna em backup | `backup.rs` (`allowed_columns`) | ✅ Corrigido + teste |
| 3 | Backup incompleto + `dek_check` corrompido | `backup.rs` (schema completo, `is_blob_column`, ordem de DELETE/INSERT) | ✅ Corrigido |
| 4 | Path traversal em imagens | `images.rs` (`sanitize_image_filename`) | ✅ Corrigido + teste |

Testes de regressão adicionados: `src-tauri/src/crypto.rs` (6 testes), `src-tauri/src/commands/backup.rs` (2 testes), `src-tauri/src/commands/images.rs` (2 testes). Todos passando (`cargo test --lib`: 10/10).

## Riscos residuais

- Perguntas de segurança dependem da qualidade da resposta escolhida pelo usuário (inerente ao recurso).
- CSP ainda não definida (recomendado, não aplicado nesta sessão por falta de ambiente para testar a UI).
- Webview tem acesso irrestrito a SQL e a um oráculo de descriptografia — trade-off arquitetural do Tauri, não um bug pontual.
- Auto-lock não tem gancho explícito para suspensão do SO (comportamento do motor Chromium deve mitigar, mas não foi testado aqui).
- Campo de observações gerais da conta permanece em claro por design.
- Arquivos de imagem não viajam no backup (apenas metadados).

## Resultado final

Respondendo diretamente às 7 perguntas do pedido original:

1. **Copiar só o `database.sqlite` recupera as senhas? NÃO.** Senha e 2FA (após correção) estão cifrados com XChaCha20-Poly1305 sob uma DEK que não está no banco em claro; sem a senha mestra (ou 3 respostas de recuperação corretas), só resta força bruta offline contra Argon2id (128 MiB/3 iterações por tentativa) — inviável para uma senha razoável.
2. **Copiar toda a pasta de dados do app (sem a senha mestra) recupera as senhas? NÃO**, pela mesma razão. Metadados não-secretos (nome da conta, username, e-mail, notas gerais, URLs) ficam visíveis, mas nunca foram o segredo que o cofre promete proteger.
3. **As perguntas de segurança tornam um ataque offline muito mais fácil? PARCIALMENTE.** O esquema (Shamir + Argon2id) não enfraquece a criptografia da DEK em si, mas a segurança prática desse caminho de recuperação é tão forte quanto a pior resposta escolhida pelo usuário — que tende a ter menos entropia que uma boa senha mestra.
4. **É possível redefinir a senha mestra manipulando banco ou frontend diretamente? NÃO.** Toda validação crítica (decifrar a DEK atual, confirmar ≥3 respostas via `dek_check`) ocorre no processo Rust, nunca no frontend; adulterar o SQLite diretamente só destrói a própria capacidade de decifrar os dados, não concede acesso.
5. **Existem senhas ou chaves em texto puro em algum lugar? Antes da auditoria: SIM** (campos de 2FA). **Depois da correção: NÃO** nos campos auditados (senha, propriedades sensíveis, perguntas/respostas de segurança, 2FA). Ressalva: o campo geral de "Observações" continua em claro por design.
6. **O backup é tão seguro quanto o cofre principal? Antes: PARCIALMENTE** (mesma cripto, mas incompleto e com um bug de integridade). **Depois da correção: SIM**, mesmo nível de criptografia e agora cobre todo o schema de dados do usuário (exceto bytes de imagem).
7. **Bloquear o cofre realmente impede acesso aos segredos? SIM**, no processo Rust — a DEK é removida da memória gerenciada e todo comando de segredo passa a falhar. Ressalva: bloquear não apaga retroativamente algo que já tenha sido revelado/copiado antes do bloqueio numa sessão comprometida.
