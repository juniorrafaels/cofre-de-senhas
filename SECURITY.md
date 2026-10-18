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
  notas) e propriedades personalizadas marcadas como sensíveis.
- **Recovery Key:** 120 bits aleatórios, embrulhando a mesma DEK com Argon2id.
- **Backups (`.vaultbackup`):** cifrados inteiros com uma senha de backup (Argon2id +
  XChaCha20-Poly1305). Restaurar sobre um cofre existente exige a senha mestra atual.
- **Rede:** o app não faz chamadas de rede. Links só abrem no navegador quando você clica.

### O que NÃO é protegido (limitações conhecidas)

| Limitação | Detalhe |
|---|---|
| **Metadados em texto claro** | Nome da conta, usuário, e-mail, URLs, status, flags de 2FA, favoritos, datas, plataformas, projetos **e as notas de projeto**, etiquetas, propriedades **não** sensíveis, texto das perguntas de segurança, histórico de alterações, configurações e imagens/avatares. Quem tiver o arquivo do cofre vê *quais* contas você tem, mas não as senhas |
| **Perguntas de segurança (legado)** | Cada resposta pode ser testada **offline e isoladamente** contra uma cópia do cofre. Por isso o recurso foi **descontinuado**: não é possível criar perguntas nem mudar respostas. Cofres que já têm perguntas continuam podendo usá-las para recuperar o acesso, e até serem removidas elas são o elo mais fraco. **Gere uma Recovery Key e exclua as perguntas** |
| Troca de senha não recriptografa os dados | A DEK não muda. Um backup ou uma cópia antiga do cofre, com a senha da época, continua abrindo os dados |
| Área de transferência | No Windows, segredos copiados são marcados para **não** entrar no Histórico (Win+V) nem na sincronização em nuvem, e são limpos depois do tempo configurado se você não tiver copiado outra coisa. Isso é um pedido ao Windows: apps ou malware que leem a área de transferência ainda podem capturar o conteúdo, e cópias que já saíram do computador não são apagadas. Usuário e e-mail são copiados normalmente |
| Bloqueio | O bloqueio por inatividade roda na interface e pode ser desativado (valor 0). O bloqueio ao minimizar vem desligado. O bloqueio no Win+L e na suspensão existe só no Windows |
| Memória | A DEK fica em memória enquanto o cofre está aberto. Algumas cópias temporárias da chave e de senhas não são zeradas. Não há proteção contra malware rodando na mesma sessão (keylogger, leitura de memória) |
| Disco | O SQLite usa WAL. Excluir um registro não garante remoção forense (WAL, SSD, cópias de sombra) |
| Senha mestra | Mínimo de 8 caracteres, sem medidor de força no backend. Use uma frase-senha longa |
| Recuperação | Esquecer a senha mestra sem Recovery Key (ou perguntas legadas) = perda definitiva dos dados |
| Builds | Os binários ainda não são assinados digitalmente |
| Plataforma | Só o Windows 10/11 é testado |

### Dependências com avisos conhecidos

- `sharks` 0.5.0 — RUSTSEC-2024-0398 (viés nos coeficientes do Shamir, sem correção). Usado
  **apenas** para recuperar cofres com perguntas legadas. Ignorado de propósito em
  `src-tauri/.cargo/audit.toml` e será removido com o suporte legado.
- Crates transitivas do Tauri marcadas como sem manutenção (`unic-*`, `proc-macro-error`) e
  `glib` (só Linux). Nenhuma afeta a build Windows em execução.
