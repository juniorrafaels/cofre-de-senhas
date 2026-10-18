# Licença do projeto

**Decisão (2026-10-18): Apache License 2.0.** Texto integral em [`LICENSE`](../../LICENSE);
avisos de atribuição e de marcas de terceiros em [`NOTICE`](../../NOTICE).

## Por que Apache-2.0

| | MIT | **Apache-2.0** | GPL-3.0 |
|---|---|---|---|
| Uso comercial | Permitido | Permitido | Permitido |
| Forks fechados | Podem | Podem | Não podem (precisam ser GPL e ter o código aberto) |
| Patentes | Nada explícito | **Concessão explícita** dos contribuidores; a licença é revogada para quem processar alegando patente | Concessão explícita |
| Marcas | Não trata | **Não concede uso do nome/marca** (seção 6) | Não concede |
| Contribuições | Implícito | Entram sob Apache-2.0 por padrão (seção 5), sem precisar de CLA | Entram sob GPL |
| Obrigação de quem redistribui | Manter o aviso | Manter `LICENSE`, `NOTICE` e indicar arquivos alterados | Fornecer o código-fonte |

A Apache-2.0 foi escolhida por ser permissiva e, ao mesmo tempo, proteger contra litígios de
patentes (relevante em software de criptografia) e deixar claro que forks não podem se apresentar
como o "Cofre de Contas" oficial.

## O que a licença não cobre

Os logos de plataformas de terceiros em `src-tauri/resources/default-platform-images/` são marcas
dos respectivos titulares e **não** estão sob a Apache-2.0. Ver [`docs/ASSETS.md`](../ASSETS.md).

## Compatibilidade com as dependências

Todas as dependências npm e Cargo usam licenças compatíveis com a Apache-2.0: MIT, Apache-2.0,
BSD, ISC, MPL-2.0 (arquivos não modificados), BSL-1.0, Unicode-3.0, Zlib, CC0, entre outras.
Ao distribuir **binários**, inclua junto um arquivo `THIRD_PARTY_LICENSES` com os avisos dessas
dependências (por exemplo, gerado com `cargo about` e `npx license-checker-rseidelsohn`).
