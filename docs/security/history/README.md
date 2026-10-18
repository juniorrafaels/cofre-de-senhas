# Histórico de autoavaliações de segurança

> Estes documentos são **autoavaliações internas** feitas durante o desenvolvimento, com auxílio de
> ferramentas de IA. **Não são auditorias independentes** e podem estar desatualizados em relação
> ao código atual. O status atual está em [`SECURITY.md`](../../../SECURITY.md)
> e [`SECURITY.md`](../../../SECURITY.md). Cada arquivo começa com um aviso que lista as
> desatualizações conhecidas. Caminhos locais e dados do ambiente do desenvolvedor foram removidos.

Ordem cronológica:

| Documento | Data | Resumo |
|---|---|---|
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | 2026-08-28 | Fase 1: revisão da arquitetura criptográfica (Argon2id, DEK, XChaCha20-Poly1305) e correção de 2FA em claro, SQL injection por nome de coluna no backup, backup incompleto e path traversal em imagens. |
| [SECURITY_AUDIT_PHASE_2.md](SECURITY_AUDIT_PHASE_2.md) | 2026-08-28 | Fase 2: cifragem de observações, remoção do fallback de texto puro, Recovery Key, CSP, cópia de segredos pelo backend e endurecimento do auto-lock. |
| [SECURITY_AUDIT_PHASE_3.md](SECURITY_AUDIT_PHASE_3.md) | 2026-08-28 | Fase 3: remoção do SQL livre da WebView (commands Rust por domínio), validação de entrada no Rust, hook nativo de Win+L/suspensão e zeroização de entradas. |
| [SECURITY_AUDIT_PHASE_4.md](SECURITY_AUDIT_PHASE_4.md) | 2026-08-28 | Fase 4: remoção do oráculo genérico `decrypt_secret`, commands de revelar/copiar por ID, verificação de posse, rate limiter e reautenticação nas operações de recuperação. |
| [SECURITY_FINAL_VALIDATION.md](SECURITY_FINAL_VALIDATION.md) | 2026-08-29 | Validação final: build de produção, testes de Recovery Key e perguntas de segurança, e o achado de que dev e release compartilham o diretório de dados. A afirmação de "nenhum bug novo" foi superada por uma revisão posterior. |
| [SECURITY_MANUAL_TESTS.md](SECURITY_MANUAL_TESTS.md) | até 2026-08-29 | Checklist de testes manuais (Win+L, suspensão, clipboard, DevTools, backup, simulação de XSS) que dependem de interação humana. |
