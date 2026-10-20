# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). O projeto usa
[versionamento semântico](https://semver.org/lang/pt-BR/) a partir da primeira versão pública.

## [Não lançado]

## [0.1.0-beta.2] - 2026-10-20

### Adicionado
- **Desbloqueio com duas senhas** (opcional, desligado por padrão): `KEK = HKDF(Argon2id(senha1) ||
  Argon2id(senha2))` protegendo a mesma DEK, com salts exclusivos, parâmetros versionados e AAD. A
  exigência é aplicada no backend; ativar, desativar e trocar reautenticam e são atômicos.
- **Segunda senha de recuperação** (opcional): envelope Argon2id + XChaCha20-Poly1305 da mesma DEK,
  independente da Recovery Key e das perguntas de segurança.
- **Bloqueio progressivo** por tentativas incorretas (opcional): 15 s, 30 s, 1 min, 5 min, 30 min,
  1 h, 2 h, 4 h; estado no SQLite, cobrado antes da verificação, válido entre janelas e instâncias,
  nunca permanente.
- **Um cofre desbloqueado por instalação**: lock exclusivo do sistema operacional, liberado ao
  bloquear/fechar e em encerramentos inesperados; a tela de desbloqueio informa quando já existe um
  cofre aberto.
- **Último login** e selo **"Atualizada"** (90 dias, renovado apenas pela ação "Marcar como
  atualizada") nas contas, com preferências de exibição separadas (coluna e selo).
- **Indicador de força** nas senhas das contas, reaproveitando o avaliador da senha mestra.
- Migrações de esquema versionadas e transacionais (`PRAGMA user_version`).
- Documentação: `docs/CREDENCIAIS_E_RECUPERACAO.md`.
- Licença Apache-2.0 (`LICENSE`) e `NOTICE` com aviso sobre marcas de terceiros.
- Guia de instalação para usuários (`docs/INSTALACAO.md`) e `Compilar instalador.bat`, que confere os
  pré-requisitos e gera o instalador com dois cliques.
- Roteiro de testes manuais e script que isola o cofre real durante os testes
  (`docs/TESTES_MANUAIS.md`, `scripts/cofre-teste-isolado.ps1`).
- Interface em português (Brasil), inglês e espanhol.
- CI (GitHub Actions): testes, checagem de tipos, build e auditoria de dependências; job manual que
  gera instaladores com SHA-256 para conferência (sem publicar).
- `SECURITY.md`, `CONTRIBUTING.md`, documentação de assets e de licença.

### Alterado
- Mensagens de erro de URL inválida traduzidas (português, inglês e espanhol) e aviso no
  formulário de conta e de plataforma.
- Configuração de build portátil: o `target-dir` absoluto saiu do repositório (ver
  `src-tauri/.cargo/config.toml.example` e `CARGO_TARGET_DIR`).
- `source-map-js` 1.2.1 → 1.2.2 e `vite` 7.3.6 → 7.3.7 (ferramentas de build; alertas do `npm audit`).
- Metadados do pacote e título da janela deixaram de usar os valores do template Tauri.
- Ícone próprio do Cofre de Contas no lugar do logo padrão do Tauri.
- `instagram.png` reduzido de 5001 px (1,3 MB) para 512 px (cofres existentes mantêm a imagem
  que já tinham).
- Comandos que reautenticam a senha mestra (alterar senha, Recovery Key, perguntas de segurança,
  importar backup, excluir o cofre) aceitam também a segunda senha quando o desbloqueio exige duas.
- Redefinir a senha mestra depois de uma recuperação volta o desbloqueio a uma senha só.
- Backups passam a incluir as novas colunas de `vault_meta` e de `accounts`; backups antigos continuam
  restauráveis. O estado do bloqueio progressivo não entra no backup e não é alterado por restaurar.
- Erros de proteção corrompida/versão desconhecida deixam de ser apresentados como "senha incorreta".

### Segurança
- Links de login/site: o backend agora só aceita `https://` e `http://` com host (rejeita
  `javascript:`, `file:`, `data:`, esquemas desconhecidos, URLs sem esquema e malformadas) e a
  capability do Tauri deixou de herdar `opener:default` (que liberava `mailto:`, `tel:` e
  "mostrar no Explorer"). Também são rejeitados barras invertidas, caracteres invisíveis/de
  inversão de texto (U+202E) e usuário/senha na URL; o esquema é gravado em minúsculas.
  URLs sem esquema (`exemplo.com`) já não podem ser salvas: digite `https://exemplo.com`.
- URLs antigas inválidas não são apagadas nem reescritas: a conta continua editável nos outros
  campos (o Rust compara com o valor gravado no banco), a interface avisa que o link não será
  aberto, e só uma URL nova ou alterada passa pela validação completa.
- Release: o `SHA256SUMS.txt` agora é gerado em LF (antes saía em CRLF e quebrava o
  `sha256sum -c`); os instaladores são publicados com nomes sem espaços
  (`Cofre-de-Contas_<versão>_x64-setup.exe`) idênticos aos do manifesto, e os arquivos
  guardados pelo GitHub são conferidos antes de publicar. Tags aceitas: `vX.Y.Z` e
  `vX.Y.Z-beta.N`; betas usam a versão completa nos manifestos e um
  `bundle.windows.wix.version` numérico (`X.Y.Z.N`) para o MSI (ver `docs/RELEASE.md`).
- CI: Actions fixadas por SHA, `ubuntu-24.04` fixo, `persist-credentials: false`; novo CodeQL
  (TypeScript/React), Dependabot e workflow de release com hashes e attestation.
- Metadados da conta cifrados em repouso (fase 1): nome da conta, categoria, usuário, e-mail,
  `login_url`, `website_url` e o detalhe do histórico passam a ser gravados como `enc:v2:` (XChaCha20-
  Poly1305 com a DEK e AAD = tabela + coluna + id da linha). Cofres antigos são migrados no
  desbloqueio (idempotente, transacional, com backup pré-migração cifrado e verificado); uma falha
  nunca impede o desbloqueio. A ordenação por nome passou do SQL para o Rust. Etiquetas, projetos e
  plataformas ficam para outra fase. Vestígios do texto puro antigo podem permanecer no disco.
- Perguntas de segurança: a criação e a edição foram reativadas (a descontinuação anterior não foi
  uma decisão do proprietário). O recurso é opcional e o aviso de riscos fica sempre visível: cada
  resposta pode ser testada offline isoladamente por quem copiar o `vault.db`. A recuperação
  continua exigindo 3 respostas corretas (limiar fixo do formato); com 1 ou 2 perguntas ela ainda
  não funciona e a interface avisa. O índice da share agora reaproveita o menor valor livre (sem
  esgotar os 255 possíveis) e adicionar/editar exige o cofre desbloqueado e a senha mestra atual.
- Importar backup sobre um cofre existente agora exige a senha mestra atual (validada no backend).
- A troca de senha "após recuperação" só é aceita quando o cofre foi aberto por um fluxo de
  recuperação. Uma sessão aberta normalmente precisa usar "Alterar senha mestra", que pede a senha
  atual.
- No Windows, senhas e propriedades sensíveis copiadas são marcadas para não entrar no Histórico da
  área de transferência (Win+V) nem na sincronização em nuvem.
- Limites superiores para os parâmetros do Argon2 lidos de arquivos (evita travamento por backup
  malicioso).
- A CSP de produção não libera mais `localhost:1420` (agora restrito a `devCsp`).

## [0.1.0-beta.1] - 2026-10-18

Primeira versão pública (pré-lançamento, publicada como ZIP de artefatos do CI, sem attestation).
