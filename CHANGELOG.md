# Changelog

Todas as mudanças relevantes deste projeto são registradas aqui.
Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/). O projeto usa
[versionamento semântico](https://semver.org/lang/pt-BR/) a partir da primeira versão pública.

## [Não lançado]

### Segurança
- Perguntas de segurança descontinuadas: não é mais possível criar perguntas nem alterar respostas,
  porque cada resposta podia ser testada offline isoladamente. Cofres que já têm perguntas continuam
  podendo usá-las para recuperação. Recomenda-se gerar uma Recovery Key e excluir as perguntas.
- Importar backup sobre um cofre existente agora exige a senha mestra atual (validada no backend).
- A troca de senha "após recuperação" só é aceita quando o cofre foi aberto por um fluxo de
  recuperação. Uma sessão aberta normalmente precisa usar "Alterar senha mestra", que pede a senha
  atual.
- No Windows, senhas e propriedades sensíveis copiadas são marcadas para não entrar no Histórico da
  área de transferência (Win+V) nem na sincronização em nuvem.
- Limites superiores para os parâmetros do Argon2 lidos de arquivos (evita travamento por backup
  malicioso).
- A CSP de produção não libera mais `localhost:1420` (agora restrito a `devCsp`).

### Alterado
- Configuração de build portátil: o `target-dir` absoluto saiu do repositório (ver
  `src-tauri/.cargo/config.toml.example` e `CARGO_TARGET_DIR`).
- `source-map-js` 1.2.1 → 1.2.2 (ferramenta de build; alerta do `npm audit`).
- Metadados do pacote e título da janela deixaram de usar os valores do template Tauri.
- Ícone próprio do Cofre de Contas no lugar do logo padrão do Tauri.
- `instagram.png` reduzido de 5001 px (1,3 MB) para 512 px (cofres existentes mantêm a imagem
  que já tinham).

### Adicionado
- Licença Apache-2.0 (`LICENSE`) e `NOTICE` com aviso sobre marcas de terceiros.
- Guia de instalação para usuários (`docs/INSTALACAO.md`) e `Compilar instalador.bat`, que confere os pré-requisitos e gera o instalador com dois cliques.
- Roteiro de testes manuais e script que isola o cofre real durante os testes
  (`docs/TESTES_MANUAIS.md`, `scripts/cofre-teste-isolado.ps1`).
- Interface em português (Brasil), inglês e espanhol.
- CI (GitHub Actions): testes, checagem de tipos, build e auditoria de dependências; job manual que gera instaladores com SHA-256 para conferência (sem publicar).
- `SECURITY.md`, `CONTRIBUTING.md`, documentação de assets e de licença.
