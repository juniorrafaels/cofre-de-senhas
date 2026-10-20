# Política de segurança

## Estágio do projeto

O Cofre de Contas é **beta** e mantido por **uma pessoa**. O código passou por revisões internas,
feitas durante o desenvolvimento e registradas em [`docs/security/history/`](docs/security/history/),
mas **nunca por uma auditoria de segurança independente**. Avalie se isso é adequado antes de
guardar nele credenciais críticas, e mantenha backups.

## Como reportar uma vulnerabilidade

**Não abra issue pública** para vulnerabilidades.

Use o **reporte privado de vulnerabilidades do GitHub**: aba **Security** do repositório →
**Report a vulnerability**.

Inclua, se possível:
- versão ou commit afetado;
- passos para reproduzir, usando **somente dados fictícios** (nunca envie seu `vault.db`, backups
  ou Recovery Key);
- impacto que você observou ou espera.

O mantenedor trabalha no projeto no tempo livre: **não há prazo garantido de resposta ou de
correção**. Reportes são tratados por ordem de gravidade. Se quiser divulgar publicamente,
combine antes uma data razoável.

## Versões suportadas

Só a versão mais recente da branch `main` (e a release mais recente, quando houver) recebe
correções.

## Modelo de segurança

### O que é protegido

- **Senha mestra:** derivada com **Argon2id** (128 MiB, 3 iterações, salt aleatório de 16 bytes),
  que gera a chave que embrulha a **DEK** (chave aleatória de 256 bits que cifra os dados).
- **Cifra:** **XChaCha20-Poly1305** (nonce aleatório de 192 bits), por campo.
- **Campos cifrados:** senha da conta, notas da conta, detalhes de 2FA (telefone, e-mail, app,
  notas), propriedades personalizadas marcadas como sensíveis e, desde a fase 1 da criptografia
  de metadados, nome da conta, categoria, usuário, e-mail, URLs e o detalhe do histórico (formato
  `enc:v2:` com AAD — ver "Criptografia de metadados da conta").
- **Recovery Key:** 120 bits aleatórios, embrulhando a mesma DEK com Argon2id.
- **Backups (`.vaultbackup`):** cifrados inteiros com uma senha de backup (Argon2id +
  XChaCha20-Poly1305). Restaurar sobre um cofre existente exige a senha mestra atual.
- **Rede:** o app não faz chamadas de rede. Links só abrem no navegador quando você clica.

### Criptografia de metadados da conta (fase 1)

- **Campos cifrados:** `accounts.name` (nome da conta), `category`, `username`, `email`,
  `login_url`, `website_url` e `account_history.detail` (o valor anterior/novo de uma troca de
  usuário, por exemplo). Valores vazios continuam `NULL` (a ausência de um campo é visível).
- **Formato:** `enc:v2:` + base64(`nonce` de 24 bytes aleatórios `||` ciphertext+tag),
  XChaCha20-Poly1305 com a **mesma DEK** do cofre (sem chave nova, fixa ou embutida).
- **AAD:** cada valor autentica `"cofre/field/v2"`, a tabela, a coluna e o **id da linha**, cada
  parte com prefixo de tamanho (u32 BE) e o id como i64 BE — sem ambiguidade entre campos. Copiar um
  ciphertext para outra conta, outra coluna ou outra tabela falha na autenticação: o campo aparece
  como ilegível (`unreadable_fields`; o nome vira `[nome ilegível #id]`, o detalhe do histórico vira
  `[detalhe ilegível]`) e **nunca** como o valor de outra conta. Como o id só existe depois do
  INSERT, a linha nasce com marcadores vazios e recebe o valor cifrado na mesma transação.
- **O prefixo não é prova de autenticidade:** quem decide é a tag Poly1305. Prefixo `enc:vN:` com
  N desconhecido = "versão desconhecida" (ilegível, não alterado). Valor sem prefixo = texto puro
  **legado** (cofre antigo ainda não migrado), aceito só para leitura/migração.
- **Migração (a cada desbloqueio, qualquer caminho: senha, perguntas ou Recovery Key):**
  idempotente e transacional. Só cifra valores legados em texto puro; não cifra duas vezes o que
  já é `enc:v2:` e autentica; deixa intactos (e conta) valores adulterados ou de versão
  desconhecida. Antes de escrever, se há algo a migrar e o banco é um arquivo, cria
  `vault.db.pre-v2.bak`: cópia do banco **cifrada com a DEK** (AAD próprio), lida de volta e
  comparada byte a byte. Cada linha é relida e verificada dentro da transação; qualquer falha =
  rollback total. Uma falha de migração **não impede o desbloqueio** (o cofre antigo continua
  legível) e a migração é tentada de novo no próximo desbloqueio. Não existe botão para restaurar
  o `.pre-v2.bak` (função `restore_premigration_backup`, testada); ele sai junto com "Excluir cofre".
  Depois de conferir que tudo está certo, você pode apagar esse arquivo manualmente.
- **Vestígios físicos antigos:** a migração liga `secure_delete` e faz `wal_checkpoint(TRUNCATE)`
  para zerar conteúdo antigo ao reescrever linhas e esvaziar o WAL, mas **não** há garantia de
  apagamento: páginas livres de operações anteriores (contas excluídas, edições), blocos antigos do
  sistema de arquivos, SSD (wear leveling), cópias de sombra do Windows, backups do próprio disco e
  o `.vaultbackup`/cópias feitas **antes** da migração podem conter o texto puro antigo.
- **Pesquisa e ordenação:** o Rust devolve a lista já descriptografada (cofre aberto) e a busca
  parcial continua no frontend sobre esses valores em memória. A ordenação por nome passou do SQL
  para o Rust, com a mesma semântica (bytes UTF-8, equivalente ao `ORDER BY` BINARY). Não há índice
  cego nem hash determinístico, então nada vaza igualdade/frequência. Ao bloquear o cofre a DEK é
  descartada; os valores já entregues à interface ficam em memória da WebView enquanto a sessão
  existe.
- **Backups e exportação:** o `.vaultbackup` continua cifrado por inteiro com a senha do backup;
  as linhas viajam como estão no banco (ids preservados, então o AAD continua válido). Restaurar
  um backup antigo traz os metadados em texto puro de volta; eles são migrados no próximo
  desbloqueio. Depois de restaurado e aberto, os dados internos **não** são "criptografados por
  causa do backup": dependem da migração. Não existe exportação em CSV/JSON em texto puro.
- **Segredos legados:** senha, notas e 2FA continuam no formato anterior (base64 de
  nonce+ciphertext, **sem AAD**): cada coluna tem um formato fixo, então não há ambiguidade, mas
  esses campos ainda podem ser trocados entre linhas por quem editar o arquivo. Migrá-los para o
  formato com AAD é uma decisão futura.
- **Fora desta fase (continuam em claro):** etiquetas, projetos (nome, descrição, notas),
  plataformas, propriedades não sensíveis e nomes de propriedades, texto das perguntas de segurança,
  status, favoritos, datas, ids, vínculos entre tabelas, flags e método de 2FA, nomes de arquivos de
  imagem e configurações.
- **Limites:** quem puder escrever no arquivo pode trocar um valor cifrado por texto puro com um
  cofre ainda não migrado, ou apagar/zerar campos; o AAD impede *copiar* ciphertext legítimo, não
  impede remoção. Malware no computador com o cofre aberto lê tudo. Não houve auditoria de
  segurança externa e independente.

### O que NÃO é protegido (limitações conhecidas)

| Limitação | Detalhe |
|---|---|
| **Metadados em texto claro (restantes)** | Etiquetas, projetos (nome, descrição **e notas**), plataformas, propriedades **não** sensíveis (e os nomes das propriedades), texto das perguntas de segurança, status, flags e método de 2FA, favoritos, datas, ids, vínculos, configurações e imagens/avatares. Nome da conta, usuário, e-mail, URLs, categoria e o detalhe do histórico **não** estão mais nessa lista **depois da migração** (cofres antigos são migrados no desbloqueio; vestígios físicos antigos podem permanecer — veja a seção abaixo). Quem tiver o arquivo vê o que sobrou, não as senhas |
| **Perguntas de segurança (opcional)** | Cada resposta protege sozinha uma share da DEK e pode ser testada **offline e isoladamente** contra uma cópia do cofre; respostas pessoais costumam ser previsíveis e mais perguntas não garantem entropia específica. O recurso é opcional e foi mantido por decisão do proprietário; uma Recovery Key aleatória é mais forte. Veja a seção abaixo |
| Troca de senha não recriptografa os dados | A DEK não muda. Um backup ou uma cópia antiga do cofre, com a senha da época, continua abrindo os dados |
| Área de transferência | No Windows, segredos copiados são marcados para **não** entrar no Histórico (Win+V) nem na sincronização em nuvem, e são limpos depois do tempo configurado se você não tiver copiado outra coisa. Isso é um pedido ao Windows: apps ou malware que leem a área de transferência ainda podem capturar o conteúdo, e cópias que já saíram do computador não são apagadas. Usuário e e-mail são copiados normalmente |
| Bloqueio | O bloqueio por inatividade roda na interface e pode ser desativado (valor 0). O bloqueio ao minimizar vem desligado. O bloqueio no Win+L e na suspensão existe só no Windows |
| Memória | A DEK fica em memória enquanto o cofre está aberto. Algumas cópias temporárias da chave e de senhas não são zeradas. Não há proteção contra malware rodando na mesma sessão (keylogger, leitura de memória) |
| Disco | O SQLite usa WAL. Excluir um registro não garante remoção forense (WAL, SSD, cópias de sombra) |
| Senha mestra | Mínimo de 8 caracteres. O medidor de força (senha mestra e senhas das contas) é uma heurística de composição no frontend, não uma medida de entropia, e nunca impede salvar. Use uma frase-senha longa |
| Desbloqueio com duas senhas (opcional) | Perder **uma** das senhas impede o desbloqueio normal; só um método de recuperação devolve o acesso. Os métodos de recuperação **não** exigem as duas senhas. Redefinir a senha após uma recuperação volta a uma senha só |
| Bloqueio progressivo (opcional) | Dificulta tentativas automatizadas **através do app**. Não protege contra quem copiou o `vault.db` (teste offline) nem contra quem controla os arquivos, o relógio ou o binário (pode apagar o contador ou adiantar o relógio). Um terceiro pode bloquear você por até 4 h por vez; a recuperação segue disponível |
| Um cofre aberto por instalação | Lock consultivo do SO por pasta de dados: coordena instâncias cooperantes do app; não impede um processo hostil de abrir o `vault.db`. Testado só no Windows; em pastas de rede/sincronizadas não é garantido |
| Datas da conta | `update_confirmed_at` (carimbo de sistema) fica em claro, como `created_at`/`updated_at`; `last_login_at` é cifrada (`enc:v2:`) |
| Recuperação | Esquecer a senha mestra sem Recovery Key e sem pelo menos 3 respostas corretas = perda definitiva dos dados |
| Builds | Os binários ainda **não são assinados digitalmente**. O SHA-256 confere integridade, não identidade do publicador; a attestation de proveniência (a partir da próxima release) dá evidência da origem do build, mas não substitui assinatura de código. O SmartScreen pode alertar |
| Plataforma | Só o Windows 10/11 é testado |

### Abertura de links externos

URLs de login/site só são aceitas se forem `https://` (ou `http://`, mantido por compatibilidade
com cofres existentes) **com o esquema escrito por extenso e com host**: `exemplo.com` não pode ser
salvo, é preciso digitar `https://exemplo.com`. Ao **salvar** contas e plataformas, o backend
rejeita `javascript:`, `file:`, `data:`, esquemas desconhecidos, barras invertidas, espaços,
caracteres invisíveis ou de inversão de texto (U+202E), portas inválidas e usuário/senha na URL
(`https://usuario:senha@host` deixaria a senha em texto claro no banco, e `https://site.com@outro.com`
engana quem lê o host). IPv6, IPv4, localhost, IDN e portas válidas são aceitos. O esquema é gravado
em minúsculas (o plugin opener compara a string crua, sensível a maiúsculas). A interface repete a
checagem ao abrir o link, e a capability do Tauri só libera `http(s)` ao plugin opener (sem
`mailto:`, `tel:` nem "mostrar no Explorer").

**URLs antigas.** Essas regras valem para URLs **novas ou alteradas**. Uma conta ou plataforma que
já tem uma URL inválida pelas regras novas **não é apagada nem reescrita**: a URL continua no cofre
(e nos backups, que não são validados ao restaurar), você continua editando os outros campos
normalmente, e a interface avisa que o link não será aberto. Para voltar a abrir, corrija a URL;
qualquer valor diferente do gravado passa pela validação completa.

### Cadeia de desenvolvimento e distribuição

- GitHub Actions fixadas por SHA de commit; Dependabot propõe atualizações (npm, Cargo e Actions).
- `cargo audit` e `npm audit` no CI. **CodeQL** analisa só o TypeScript/React: **não cobre o
  backend Rust**, onde ficam criptografia e banco; ali valem clippy, `cargo audit` e os testes.
- Releases por tag `vX.Y.Z` (estável) ou `vX.Y.Z-beta.N` (beta; outros sufixos são recusados):
  testes, auditorias e build numa máquina limpa do GitHub, instaladores publicados
  individualmente (nomes sem espaços) com `SHA256SUMS.txt` e attestation. A versão da tag precisa
  bater exatamente com `package.json`, `tauri.conf.json` e `Cargo.toml` (betas também com o
  `bundle.windows.wix.version` numérico do MSI), então dois betas nunca viram a mesma versão. Os
  arquivos guardados pelo GitHub são baixados de volta e conferidos antes de publicar. Tags
  estáveis criam só um **rascunho**, que o mantenedor revisa antes de publicar. Veja
  [`docs/RELEASE.md`](docs/RELEASE.md).
- **Proteção de tags `v*`:** o workflow confere que a tag ainda aponta para o commit compilado e
  que ele está na `main`, mas isso **não substitui** a regra de proteção de tags do repositório
  (Settings → Rules → Rulesets: bloquear exclusão e atualização de tags `v*`), que precisa ser
  configurada no GitHub.

### Credenciais, recuperação, bloqueio e exclusividade (opcionais)

O desbloqueio com duas senhas (protocolo `dual-v1`: dois Argon2id + HKDF-SHA256 + AEAD com AAD), a
segunda senha de recuperação (envelope independente da DEK), o bloqueio progressivo (15 s a 4 h) e a
exclusividade de cofre aberto estão descritos, com formatos, estratégia de compatibilidade e
limites, em [docs/CREDENCIAIS_E_RECUPERACAO.md](docs/CREDENCIAIS_E_RECUPERACAO.md). Pontos de
segurança centrais:

- Nenhuma opção é ligada automaticamente em cofres existentes; a DEK nunca muda e nenhum método de
  recuperação é invalidado por outro.
- A exigência de duas senhas é aplicada no backend; uma senha isolada não obtém a DEK por nenhum
  caminho alternativo.
- O bloqueio é contabilizado no backend e persiste entre reinícios e instâncias; nunca é permanente
  (teto de 4 h) e metadados corrompidos de proteção são reportados como corrupção, não como "senha
  incorreta".
- Senhas, DEK e chaves derivadas não são gravadas em disco nem em logs (há testes que varrem os
  arquivos do banco e o código de produção).
- **Não houve auditoria externa independente** destes protocolos.

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
  - `sharks` 0.5.0 tem o aviso RUSTSEC-2024-0398 (coeficientes do polinômio sorteados em 1..=255,
    nunca 0). Pelo código da crate, o viés é pequeno e, neste app, os coeficientes vêm de um
    ChaCha20 semeado pela própria DEK; o elo fraco prático são as respostas, não esse viés. Não foi
    feita análise formal do impacto. A crate aparenta não ter manutenção.
- **Se você perder a senha mestra** e não tiver Recovery Key nem pelo menos 3 respostas corretas
  entre as perguntas sorteadas, os dados são perdidos definitivamente.
- **Cofres já existentes** com perguntas continuam funcionando sem migração, e os backups
  `.vaultbackup` incluem as perguntas (cifradas como no banco).

### Dependências com avisos conhecidos

- `sharks` 0.5.0 — RUSTSEC-2024-0398 (viés nos coeficientes do Shamir, sem correção). Usado
  na recuperação por perguntas de segurança (criar, editar e recuperar). Ignorado de propósito em
  `src-tauri/.cargo/audit.toml`; só pode sair se o mecanismo mudar (decisão do proprietário).
- Crates transitivas do Tauri marcadas como sem manutenção (`unic-*`, `proc-macro-error`) e
  `glib` (só Linux). Nenhuma afeta a build Windows em execução.
