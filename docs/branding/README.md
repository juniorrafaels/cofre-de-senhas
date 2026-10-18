# Identidade visual

`cofre-icon.svg` é a fonte do ícone do Cofre de Contas (porta de cofre com roda de segredo e
buraco de fechadura, em azul e verde-água). É um desenho original do projeto, sob a mesma licença
do código (Apache-2.0).

Para regenerar os ícones do app depois de editar o SVG:

```powershell
npx tauri icon docs/branding/cofre-icon.svg
Remove-Item -Recurse src-tauri/icons/android, src-tauri/icons/ios   # não usados
Copy-Item docs/branding/cofre-icon.svg public/favicon.svg
```
