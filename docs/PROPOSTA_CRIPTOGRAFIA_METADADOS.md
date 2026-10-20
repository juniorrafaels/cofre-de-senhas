# Proposta: criptografar e-mail, usuário e demais metadados em repouso

Status: **fase 1 IMPLEMENTADA** (nome da conta, categoria, usuário, e-mail, URLs e detalhe do
histórico; etiquetas, projetos e plataformas ficam fora). O comportamento real e os limites estão em
`SECURITY.md` (seção "Criptografia de metadados da conta"); este arquivo guarda o racional original.
Baseada na auditoria
do teste `audit_no_account_or_history_marker_appears_in_plaintext_on_disk_or_in_backups`
(`src-tauri/src/commands/accounts.rs`).

## Estado atual (verificado)
Em claro no `vault.db`: nome da conta, categoria, usuário, e-mail, `login_url`, `website_url`,
etiquetas e o texto do histórico (inclusive usuário anterior → novo). Cifrados (XChaCha20-Poly1305,
nonce aleatório de 24 bytes por valor, chave = DEK): senha, notas, 2FA (4 campos), propriedades
marcadas como sensíveis. O `.vaultbackup` é cifrado inteiro (nenhum marcador aparece).

## Achados que a proposta resolve
1. **Usuário/e-mail/URLs/nome em claro** para quem tiver só o arquivo (média: revela quais serviços e
   contas a pessoa tem, não as senhas).
2. **Histórico grava usuário antigo e novo em claro** (`App.tsx`, `username_changed`).
3. **Sem dados autenticados associados (AAD):** `crypto::encrypt` não amarra o ciphertext a
   conta/campo. Quem puder editar o arquivo pode trocar blobs entre contas ou campos (ex.: copiar a
   senha cifrada de A para B) sem a falha ser detectada. Exige acesso de escrita ao arquivo.

## Arquitetura recomendada
- Nova versão de formato `enc:v2:` (base64 de `nonce || ct`) usando **a mesma DEK** (já protegida pela
  senha mestra / Recovery Key / perguntas). Nenhuma chave nova, fixa ou embutida.
- **AAD** = `"cofre/v2|" + tabela + "|" + coluna + "|" + id_da_linha` em cada `encrypt`/`decrypt`,
  impedindo troca de valores entre campos e contas. Campos antigos (sem prefixo) continuam legíveis.
- Campos-alvo (fase 1): `username`, `email`, `login_url`, `website_url`, `category`, `history.detail`.
  Fase 1 (decidida): inclui também `name`. Fora: nomes de etiquetas/projetos/plataformas.
- **Pesquisa/filtro:** já é feito no frontend (`src/lib/filter.ts`) sobre a lista que o Rust devolve
  descriptografada com o cofre aberto — continua funcionando, inclusive busca parcial. Não é preciso
  índice cego nem hash determinístico, e **não se recomenda** (vazam igualdade/frequência e são
  vulneráveis a dicionário para e-mails e usuários).
- **Ordenação:** hoje `ORDER BY a.name` no SQL; se `name` for cifrado, ordenar em Rust/JS após decifrar.
- **Migração versionada e atômica** (transação única, só com o cofre desbloqueado, pois precisa da
  DEK): backup verificado do `vault.db` antes; reescrever cada linha para `enc:v2:`; marcar
  `schema_version`; falha no meio = rollback da transação. Cofre antigo aberto por perguntas ou
  Recovery Key migra do mesmo jeito (a DEK é a mesma).
- Backups antigos: o `.vaultbackup` guarda as linhas como estão; ao restaurar, a migração roda no
  próximo desbloqueio (dados antigos continuam legíveis até lá).

## Limites honestos
- Páginas livres, `-wal` e SSD podem reter valores antigos em claro depois da migração; só um
  `VACUUM` e a sobrescrita do arquivo reduzem isso, sem garantia forense.
- Continuam visíveis: contagem de linhas, tamanhos aproximados dos campos, datas, flags, ids,
  vínculos entre tabelas, nomes de arquivos de imagem e o texto das perguntas de segurança (a menos
  que também sejam cifrados — exigiria outra decisão, pois são lidas com o cofre bloqueado).
- Com o cofre aberto, um computador comprometido lê tudo.

## Addendum: novas colunas (datas da conta)
- `accounts.last_login_at` (data informada pelo usuário) é tratada como metadado do usuário: entra em
  `migration::METADATA_COLUMNS` e é gravada como `enc:v2:` com AAD (tabela, coluna, id). Valores em
  texto puro (de um backup, por exemplo) são cifrados pela migração no desbloqueio, como os demais.
- `accounts.update_confirmed_at` é um carimbo de sistema em UTC, mantido em claro como `created_at` e
  `updated_at` (não é dado digitado pelo usuário; revela apenas quando houve a confirmação).
- As colunas de credenciais novas (`unlock_*`, `recovery_pw_*`) guardam só sais, parâmetros do KDF e
  envelopes autenticados; ver `docs/CREDENCIAIS_E_RECUPERACAO.md`.
