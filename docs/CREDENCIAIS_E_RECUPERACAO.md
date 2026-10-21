# Credenciais, recuperação, bloqueio e exclusividade do cofre

Documento técnico das opções de segurança opcionais adicionadas ao Cofre de Contas. Descreve o
que existe **no código**, como cada formato foi escolhido e o que **não** é garantido.

> **Nada aqui passou por auditoria independente.** O projeto não teve auditoria externa; a
> criptografia usa primitivas conhecidas (Argon2id, XChaCha20-Poly1305, HKDF-SHA256), mas a
> composição dos protocolos descritos abaixo foi desenhada e revisada apenas pelos mantenedores e
> pelas ferramentas que os auxiliam. Trate-os como "revisados internamente", não como "auditados".

## Visão geral

| Recurso | Padrão | Onde ativar | O que muda no disco |
|---|---|---|---|
| Desbloqueio com duas senhas | **Desligado** | Configurações → Segurança | `vault_meta`: `unlock_policy`, `unlock2_salt`, `unlock2_kdf_params`; `wrapped_dek` é substituído |
| Segunda senha de recuperação | **Desligada** | Configurações → Segurança | `vault_meta`: `recovery_pw_*` (envelope independente da DEK) |
| Bloqueio progressivo | **Desligado** | Configurações → Segurança | tabela `auth_throttle` (fora do backup) |
| Um cofre aberto por instalação | **Sempre ativo** | — | arquivo `vault-unlocked.lock` na pasta de dados (lock do SO, não grava nada) |
| Último login / selo "Atualizada" | Sem datas | Formulário e ficha da conta; Configurações → Aparência | `accounts.last_login_at` (cifrada), `accounts.update_confirmed_at` |
| Indicador de força | Sempre visível ao digitar | Formulário da conta | nada |

A **DEK nunca muda** por causa de nenhuma destas opções: trocar, ativar ou desativar credenciais só
troca o "envelope" que a protege. Os dados não são recifrados.

## Estratégia de compatibilidade (cofres e backups antigos)

* **Migração versionada** (`PRAGMA user_version`, ver `db::MIGRATIONS`): a migração 1 adiciona só
  colunas opcionais (`NULL`) e a tabela `auth_throttle`. Roda dentro de `BEGIN IMMEDIATE`
  (transacional e serializada entre instâncias), relê a versão dentro da transação e é idempotente.
  Uma falha desfaz tudo — sem colunas ou tabelas parciais e sem avançar `user_version`.
* **Cofre antigo**: `unlock_policy = NULL` significa exatamente o formato de sempre (uma senha,
  `wrapped_dek = XChaCha20-Poly1305(Argon2id(senha), DEK)` sem AAD). Nenhuma opção nova é ligada
  automaticamente; nenhum formato existente foi alterado.
* **Backups** (`VLTBKUP1`): o `vault_meta` inteiro viaja (as colunas novas foram incluídas na lista
  de colunas permitidas e na lista de colunas BLOB). Backup **antigo** restaura sem as colunas novas
  (ficam `NULL` = comportamento legado: uma senha, sem segunda senha de recuperação). Backup **novo**
  não é restaurável por uma versão antiga do app (coluna desconhecida é recusada de propósito).
  `auth_throttle` **não** entra no backup e **não** é apagada por uma restauração: restaurar um
  backup antigo não zera contador nem desliga a política.
* **Consequência importante**: restaurar um backup traz de volta as credenciais **da época do
  backup** (a DEK era a mesma, então os dados abrem). Se o backup é anterior à ativação das duas
  senhas, o cofre volta a abrir com uma senha só.
* **Metadados `enc:v2:`**: `accounts.last_login_at` entra na lista de colunas migradas
  (`migration::METADATA_COLUMNS`) e é gravada já como `enc:v2:` com AAD (tabela, coluna, id da linha).
  `update_confirmed_at` é um carimbo de sistema em UTC, em claro, como `created_at`/`updated_at`.

## Desbloqueio com duas senhas

Protocolo `dual-v1` (implementado em `src-tauri/src/auth.rs`):

```
K1  = Argon2id(senha1, kdf_salt,       kdf_params)          (salts exclusivos, 16 bytes aleatórios)
K2  = Argon2id(senha2, unlock2_salt,   unlock2_kdf_params)
KEK = HKDF-SHA256(salt = "cofre/unlock/dual-v1/hkdf-salt",
                  ikm  = len(K1) || K1 || len(K2) || K2,    (prefixo de tamanho: sem ambiguidade)
                  info = "cofre/unlock/dual-v1/kek")
wrapped_dek = XChaCha20-Poly1305(KEK, DEK, AAD = contexto || len(salt1)||salt1 || len(salt2)||salt2)
```

* `wrapped_dek` é **substituído**: não resta nenhum envelope que aceite só a senha 1. Com uma senha
  isolada (ou as duas trocadas de ordem) nem dá para confirmar se ela "estava certa" — o custo de
  adivinhar é o produto dos custos das duas senhas.
* A exigência é aplicada **no backend** (`auth::authenticate`/`unwrap_dek`). Senha 2 ausente em
  cofre `dual` devolve `E_SECOND_PASSWORD_REQUIRED`, sem gastar tentativa do bloqueio progressivo.
* Parâmetros do Argon2 de ambos os envelopes são validados contra os limites do projeto
  (`KdfParams::is_within_bounds`) antes de qualquer derivação; política desconhecida
  (`dual-v9`) ou metadados ilegíveis viram "dados de proteção corrompidos" — **não** "senha incorreta".
* Ativar, desativar e trocar a segunda senha reautenticam as credenciais **atuais** no próprio
  comando, gravam tudo numa única `UPDATE` dentro de `BEGIN IMMEDIATE`, **releem o envelope gravado**
  e só dão `COMMIT` se as credenciais novas devolverem exatamente a mesma DEK. Qualquer falha desfaz.
* Trocar a senha mestra num cofre `dual` mantém a senha 2 e exige as duas atuais.
* A segunda senha precisa ter ≥ 8 caracteres e ser diferente da primeira.

### Risco (mostrado na interface antes da ativação)

Perder **qualquer uma** das duas senhas impede o desbloqueio normal. Só um método de recuperação
devolve o acesso. Sem nenhum configurado, os dados ficam inacessíveis. A interface exige um aceite
explícito antes de ativar.

## Segunda senha de recuperação

Terceiro caminho (além de Recovery Key e perguntas/Shamir) para obter a **mesma DEK**:

```
KEK_r = Argon2id(senha_de_recuperação, recovery_pw_salt, recovery_pw_kdf_params)
recovery_pw_wrapped_dek = XChaCha20-Poly1305(KEK_r, DEK, AAD = "cofre/recovery-password/v1" || len(salt) || salt)
```

* Funciona com o cofre **bloqueado** e sem a DEK de uma sessão: o envelope guarda a DEK diretamente
  (como a Recovery Key). Também funciona se a senha mestra — ou as duas senhas — foram perdidas.
* Nada da senha é armazenado; salt exclusivo por configuração; nonce aleatório de 24 bytes.
* Ativar/trocar/desativar são operações sensíveis: exigem o cofre desbloqueado **e** reautenticação
  (uma ou duas senhas), com releitura e verificação antes do `COMMIT`.
* Erros distintos: formato inválido (< 8 caracteres), método não configurado, dados corrompidos
  (envelope parcial, parâmetros fora dos limites, JSON inválido), senha incorreta.
  Só "senha incorreta" conta como tentativa no bloqueio progressivo.

## Como os métodos de recuperação interagem

| Método | Guarda | Depende de | Afetado por trocar senha/ativar duas senhas? |
|---|---|---|---|
| Senha mestra (ou duas senhas) | envelope `wrapped_dek` | credenciais | — (é o que muda) |
| Recovery Key | envelope próprio (`recovery_key_*`) | só a chave | **Não** |
| Perguntas de segurança (Shamir, limiar 3) | shares derivadas da DEK | respostas | **Não** |
| Segunda senha de recuperação | envelope próprio (`recovery_pw_*`) | só a senha | **Não** |

* Como a DEK nunca muda, nenhum método fica invalidado silenciosamente por outro. Há testes
  automatizados que ativam/trocam/desativam cada opção e conferem que os demais métodos seguem
  devolvendo a mesma DEK.
* **Recuperação não exige as duas senhas** — por desenho: ela existe justamente para quando as senhas
  foram perdidas. Proteja a Recovery Key, as respostas e a segunda senha de recuperação tanto quanto
  as senhas de desbloqueio.
* **Redefinir a senha mestra depois de uma recuperação** grava **uma** senha nova e volta a política
  para `single` (a interface avisa). Manter a política `dual` sem as senhas antigas deixaria o cofre
  sem como ser reaberto. Reative em Configurações se quiser.
* Todo desbloqueio (senha, Recovery Key, perguntas, segunda senha de recuperação) também respeita a
  exclusividade de cofre aberto, antes de verificar qualquer credencial.

## Bloqueio progressivo por tentativas incorretas

Tabela (falhas consecutivas → espera): 1 → 15 s · 2 → 30 s · 3 → 1 min · 4 → 5 min · 5 → 30 min ·
6 → 1 h · 7 → 2 h · 8 ou mais → **4 h** (teto).

* **Opcional, desligado por padrão** (cofres existentes não mudam). Ligar/desligar reautentica as
  credenciais atuais. Escopos independentes para o desbloqueio e para a segunda senha de recuperação;
  a política vale para os dois.
* **Contabilizado no backend** (`lockout.rs`), no SQLite (`auth_throttle`): persiste após reiniciar e
  vale entre janelas e instâncias, que compartilham o banco. Cada tentativa é **cobrada antes** de a
  senha ser verificada, dentro de `BEGIN IMMEDIATE`: duas instâncias disparando ao mesmo tempo não
  furam o contador. Tentativas durante um bloqueio ativo são recusadas **sem** verificar a senha e
  sem aumentar a contagem. Senha válida zera a sequência.
* **O que não conta como senha incorreta**: segunda senha ausente, formato inválido, metadados
  corrompidos, erro interno/SQLite, "outra instância já aberta". A cobrança é devolvida
  (`Ticket::refund`) se a falha não foi de senha.
* **Relógio**: usa o relógio de parede (precisa sobreviver a reinício, suspensão e hibernação, o que
  um relógio monotônico não faz). O tempo restante é sempre limitado à espera daquela falha: **voltar
  o relógio nunca alonga** o bloqueio além do previsto (e nunca o cria permanente). **Adiantar** o
  relógio encurta a espera — limitação conhecida.
* **Estado corrompido** (tipo inválido, valor fora de faixa) falha **fechado, porém limitado**: vira
  o bloqueio máximo (4 h) a partir de agora, é regravado em estado válido e expira sozinho.
* **Sem bloqueio permanente / recuperação**: nenhuma espera passa de 4 h e só novas tentativas
  erradas a renovam. Quem não consegue entrar tem: (1) esperar o tempo mostrado na tela; (2) usar a
  Recovery Key, as perguntas ou a segunda senha de recuperação — que **não** dependem do bloqueio do
  desbloqueio normal (a segunda senha de recuperação tem contador próprio).
* **Limites honestos**: quem controla o computador, os arquivos do aplicativo, o relógio ou o binário
  pode apagar a linha de `auth_throttle`, adulterar o banco ou trocar o app. Isso dificulta tentativas
  **automatizadas através do app**; não protege contra um atacante que copiou o `vault.db` e testa
  senhas offline (nesse caso só a força da senha e o custo do Argon2id protegem). Um terceiro com
  acesso físico pode errar a senha de propósito e manter você bloqueado até 4 h por vez.

## Um cofre aberto por instalação (exclusividade entre instâncias)

* O primeiro desbloqueio adquire um **lock exclusivo do sistema operacional** sobre
  `<pasta de dados>/vault-unlocked.lock` (`File::try_lock`: `LockFileEx` no Windows, `flock` no
  Linux/macOS) e o guarda dentro da sessão. Bloquear o cofre, o auto-lock, o bloqueio do Windows e o
  fim do processo soltam o lock. O lock é adquirido **antes** de verificar credenciais (uma segunda
  instância não gasta tentativas nem descobre se a senha estava certa) e vale para todos os
  caminhos de desbloqueio e para criar cofre.
* A tela de desbloqueio da outra instância mostra "já existe um cofre aberto" e reconsulta a cada 3 s;
  ao bloquear a primeira, a segunda é liberada.
* **Encerramento inesperado**: o SO libera o lock quando o processo morre (kill, crash, queda de
  energia). Não há arquivo de PID para "recuperar" e **não há heartbeat nem expiração por tempo** —
  por isso uma instância apenas suspensa, hibernando ou pausada por muito tempo **nunca** perde o lock
  para outra. Há teste com processos reais, inclusive com o dono morto à força.
* **Diferenças entre sistemas** (honesto): o desenvolvimento e todos os testes rodaram em **Windows**.
  Em Linux/macOS o mesmo código usa `flock` (lock consultivo): funciona entre processos cooperantes,
  mas **não foi testado nesses sistemas**. Em pastas de dados em rede ou sincronizadas (NFS, alguns
  clientes de nuvem) o comportamento do lock depende do sistema e **não é garantido**. O app hoje só é
  suportado/testado no Windows 10/11.
* **Escopo**: o lock é por pasta de dados (uma instalação). Duas cópias do app apontando para pastas
  diferentes (ex.: o perfil isolado de `scripts/cofre-teste-isolado.ps1`, que renomeia a pasta) não se
  enxergam. O lock é consultivo: não impede um processo hostil de abrir o `vault.db` diretamente.
* Exigência de toolchain: `File::try_lock` é da biblioteca padrão do Rust ≥ 1.89.

## Última data de login e selo "Atualizada"

* **Último login** (`last_login_at`): data informada pelo usuário (`YYYY-MM-DD`, sem fuso), opcional,
  editável no formulário. É distinta de `created_at`, `updated_at` e da confirmação de atualização.
  Datas inválidas ou depois de "amanhã" são recusadas pelo backend.
* **Selo "Atualizada"** (`update_confirmed_at`): instante UTC gravado **somente** pela ação explícita
  "Marcar como atualizada" (comando `mark_account_updated`, que também registra o evento no histórico).
  Editar, abrir ou listar a conta nunca o cria nem o renova; a ação não altera `updated_at` nem
  `last_login_at` (não "inventa" um login).
* **Validade**: 90 × 24 h exatos a partir do instante confirmado (UTC): fuso e horário de verão não
  deslocam o prazo. No instante exato dos 90 dias o selo expira. Data ausente, ilegível ou no futuro
  além de 5 min de folga nunca é exibida como válida. A interface mostra a data da confirmação e os
  dias restantes. Cálculo duplicado e testado nas duas pontas (`account_status.rs`, `accountBadge.ts`).
* **Preferências de exibição** (não alteram dados): a coluna "Último login" é ligada na lista de
  colunas (`list_columns`, chave `last_login`) e o selo tem a preferência `show_updated_badge`. O app é
  monousuário e não tem permissões administrativas; nada foi inventado nesse sentido.

## O que ainda não foi auditado nem testado

* Nenhum destes protocolos passou por auditoria externa independente.
* Os comandos `#[tauri::command]` (finos) não foram exercitados por um runtime Tauri de teste; os
  núcleos que eles chamam foram testados com conexões SQLite reais/em memória, e o ciclo
  desbloquear → bloquear → recuperar → reabrir foi exercitado nesse nível. Veja
  `docs/TESTES_MANUAIS.md` para os passos manuais com o app aberto.
* Exclusividade entre processos: testada com processos reais **no Windows**; Linux/macOS não testados.
* Vestígios de dados antigos no disco (WAL, páginas livres, SSD) não são tratados por estas opções.

## Perguntas de segurança: o Shamir do Cofre (dealer v1, congelado)

As shares das perguntas são calculadas **de forma determinística a partir da DEK**
(`share_for_index`: seed = HKDF-SHA256(DEK, contexto), ChaCha20, polinômios de grau 2 sobre
GF(2^8), um por byte da DEK, limiar 3, shares em x = 1..=255). Por isso adicionar ou remover uma
pergunta recalcula a share do índice sem precisar das respostas antigas — mas também significa que
**toda share nova precisa cair exatamente no mesmo polinômio das gravadas**.

### Alerta do `sharks` (RUSTSEC-2024-0398 / GHSA-jp37-5qhw-mffw)

* **Causa:** `sharks` ≤ 0.5.0 sorteia os coeficientes aleatórios em `[1, 255]` em vez de `[0, 255]`.
  Quem vê uma share a menos que o limiar pode descartar candidatos ao segredo (um coeficiente nulo
  seria impossível). Segundo o advisory (Cure53), a exploração exige o **mesmo segredo repartido
  centenas de vezes (≈ 500–1500)** com polinômios independentes. A reconstrução **não é afetada**.
* **No Cofre:** o polinômio é derivado da DEK e é sempre o mesmo para uma DEK; não existem
  repartições independentes do mesmo segredo, e rotacionar a DEK cria outro segredo. Com 2 de 3
  shares conhecidas, o viés elimina no máximo 2 de 256 candidatos por byte (≈ 0,0113 bit por byte,
  ≈ 0,36 bit em 256). Além disso, cada share fica cifrada por uma chave derivada de uma resposta.
  O risco prático continua sendo a previsibilidade das respostas (ver `SECURITY.md`).
* **Por que não trocar por outra crate:** não existe versão corrigida de `sharks`; o fork
  `blahaj` sorteia em `[0, 255]`, o que produz **outro polinômio** para a mesma DEK. Um cofre com
  perguntas antigas que adicionasse uma pergunta nova passaria a misturar shares de dois
  polinômios e a recuperação devolveria uma DEK errada (há teste que demonstra isso). Regerar as
  shares antigas exigiria as respostas antigas, que o app não guarda.
* **O que foi feito:** a crate foi removida e o algoritmo vive em `src-tauri/src/shamir.rs`
  (corpo GF(2^8) com polinômio 0x11d, avaliação de Horner, interpolação de Lagrange). O dealer
  **v1** reproduz bit a bit o do `sharks` 0.5.0, incluindo o consumo do RNG; a recuperação também
  recusa abscissas repetidas e shares de tamanhos diferentes. Compatibilidade verificada por:
  teste diferencial contra o `sharks` (todos os x, seeds, tamanhos de segredo e limiares) executado
  antes da remoção; vetores gravados do `sharks` e do `share_for_index` antigo
  (`security_questions::tests`, `shamir::tests`); e os testes existentes de adicionar/editar/
  remover perguntas e recuperar.
* **Formato persistido:** inalterado (`wrapped_share = XChaCha20-Poly1305(chave da resposta,
  [x, y0..y31])`; nenhuma migração). Cofres e backups existentes seguem válidos.
* **Proposta para o futuro (não implementada):** um *dealer v2* com coeficientes em `[0, 255]` só
  pode valer para perguntas **criadas depois** de um marcador de versão persistido
  (`vault_meta`), com migração de esquema e convivência explícita v1/v2 por cofre; como o viés v1
  não é explorável neste desenho, a decisão fica com o mantenedor.

### Dependências que fixam o formato

`rand` 0.8 e `rand_chacha` 0.3 geram o fluxo de coeficientes do dealer v1 (o sorteio uniforme em
`[1, 255]` e o ChaCha20). As versões 0.10 usam `rand_core` 0.10 e não compilam com o código atual
(`from_seed`, `OsRng`, `thread_rng`, `gen_range` mudaram) e, mesmo compilando, o algoritmo de
amostragem uniforme pode diferir. Qualquer migração precisa passar nos vetores gravados antes de
ser aceita; ver `.github/dependabot.yml`.
