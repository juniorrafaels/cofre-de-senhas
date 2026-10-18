# Assets incluídos no Cofre de Contas: origem e licença

| Asset | Local | Origem | Licença / situação |
|---|---|---|---|
| Ícone do aplicativo | `src-tauri/icons/` (gerado), fonte em `docs/branding/cofre-icon.svg`, favicon em `public/favicon.svg` | Desenho original do projeto | Apache-2.0, junto com o código |
| Ícones da interface | `lucide-react` (npm) | Projeto Lucide | ISC; aviso incluído no pacote |
| Logos das plataformas (18 arquivos) | `src-tauri/resources/default-platform-images/` | Desconhecida: os arquivos não têm metadados de autoria ou licença | **Marcas registradas de terceiros, fora da licença do projeto.** Ver abaixo |
| `public/tauri.svg`, `public/vite.svg`, `src/assets/react.svg` | Template do Tauri/Vite | Logos do Tauri, Vite e React (MIT) | Restos do template, não usados pela interface |
| Fontes | — | Nenhuma fonte embarcada (a interface usa fontes do sistema) | — |

## Logos de plataformas

**Decisão (2026-10-18): manter os arquivos, fora da licença do projeto, com aviso de marcas**
(README e [`NOTICE`](../NOTICE)).

- Os logos são usados **só para identificar** a plataforma de cada conta (uso nominativo). O
  projeto não tem afiliação com essas empresas nem endosso delas.
- A Apache-2.0 do projeto **não** se aplica a esses arquivos. Quem redistribuir o Cofre deve
  respeitar as diretrizes de marca de cada titular.
- `instagram.png` foi reduzido de 5001×5001 px (1,3 MB) para 512×512 px (145 KB). Cofres já
  existentes continuam usando a imagem que já tinham salvo; só cofres novos recebem a versão
  reduzida.

### Antes de distribuir instaladores (recomendado)

Trocar os 18 arquivos por versões de origem rastreável, por exemplo os SVGs do
[Simple Icons](https://simpleicons.org) (dados CC0; as diretrizes de marca de cada titular
continuam valendo), convertidos para PNG ou WebP. Isso exige atualizar o teste
`fresh_install_physically_copies_every_real_default_image` em `src-tauri/src/db.rs`.

O app já tolera a ausência de um logo: `provision_default_platform_images_at` pula o arquivo que
faltar sem falhar a inicialização.
