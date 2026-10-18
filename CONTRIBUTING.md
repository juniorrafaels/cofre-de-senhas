# Como contribuir com o Cofre de Contas

Obrigado pelo interesse! O projeto é mantido por uma pessoa, no tempo livre. Contribuições são
bem-vindas, mas revisões e respostas podem demorar. Não há prazo garantido.

## Antes de tudo: segurança e privacidade

- **Nunca** anexe seu `vault.db`, arquivos `.vaultbackup`, Recovery Key, capturas de tela com dados
  reais ou logs com dados pessoais em issues ou pull requests.
- Encontrou uma vulnerabilidade? **Não abra issue pública.** Siga o [SECURITY.md](SECURITY.md).
- Para testar, use um cofre de teste com dados fictícios. O modo de desenvolvimento usa a **mesma
  pasta de dados** do app instalado (`%APPDATA%\<identificador do app>\`). Se você usa o Cofre de
  verdade na mesma máquina, faça backup e renomeie essa pasta antes de desenvolver.

## Ambiente de desenvolvimento

Siga "Compilar a partir do código-fonte" no [README](README.md#compilar-a-partir-do-código-fonte-desenvolvedores). Resumo:

```powershell
npm ci
npm run tauri dev
```

Opcional: para manter a pasta de build do Rust (vários GB) fora de uma pasta sincronizada, defina
`CARGO_TARGET_DIR` ou copie `src-tauri/.cargo/config.toml.example` para `config.toml`.

## Antes de abrir um pull request

Rode tudo o que o CI roda:

```powershell
npx tsc --noEmit
npm test
npm run build
cd src-tauri
cargo test --lib --locked
cargo clippy --locked --all-targets
```

## Regras para mudanças

- **Criptografia, recuperação, backup, bloqueio e comandos IPC:** explique o modelo de ameaça na
  descrição do PR e inclua testes, inclusive os casos de falha (senha errada, arquivo adulterado,
  cofre bloqueado). Não implemente primitivas criptográficas próprias; use as crates RustCrypto já
  usadas.
- **Formato do cofre ou do backup:** toda mudança precisa de migração compatível, testes com dados
  sintéticos e plano de rollback. Cofres existentes não podem ficar inacessíveis.
- **Validação no backend:** regras de segurança ficam no Rust, nunca só na interface.
- **Sem rede:** o app não faz chamadas de rede. Qualquer recurso que precise de rede deve ser
  discutido numa issue antes.
- **Textos da interface:** adicione as chaves nos três idiomas (`src/i18n/locales/pt-BR.ts`, `en.ts`,
  `es.ts`).
- **Dependências:** evite adicionar novas. Se precisar, justifique e confira a licença e o
  `cargo audit` / `npm audit`.
- Commits pequenos e com mensagem descritiva. Um assunto por PR.

## Licença das contribuições

Ao enviar uma contribuição, você concorda que ela seja distribuída sob a licença do projeto
(Apache License 2.0, ver [`LICENSE`](LICENSE)), conforme a seção 5 dessa licença.
