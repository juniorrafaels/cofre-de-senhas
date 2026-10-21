# Como instalar e começar a usar o Cofre de Contas

Guia para quem quer **usar** o Cofre de Contas no Windows. Não precisa saber programar.

- [Caminho 1: baixar o instalador pronto](#caminho-1-baixar-o-instalador-pronto) (o mais fácil)
- [Caminho 2: gerar o instalador a partir do código](#caminho-2-gerar-o-instalador-a-partir-do-código)
- [Primeiros passos depois de instalar](#primeiros-passos-depois-de-instalar)
- [Atualizar, desinstalar e onde ficam os dados](#atualizar-desinstalar-e-onde-ficam-os-dados)

**Requisitos:** Windows 10 (64 bits) ou Windows 11.

---

## "Baixei o projeto e só vejo pastas com código. Qual arquivo eu abro?"

Se você clicou em **Code → Download ZIP** no GitHub (ou usou `git clone`), você baixou o
**código-fonte**, não o aplicativo. Nessa pasta não existe um `.exe` pronto para abrir. Você tem
duas opções:

1. **Baixar o instalador pronto** na página **Releases** do repositório (caminho 1, abaixo).
2. **Gerar o instalador** a partir desse código com o arquivo **`Compilar instalador.bat`**
   (caminho 2, abaixo).

---

## Caminho 1: baixar o instalador pronto

> Se a página **Releases** ainda não tiver nenhuma versão publicada, use o caminho 2.

1. Na página do projeto no GitHub, clique em **Releases** (coluna da direita) e abra a versão mais
   recente.
2. Em **Assets**, baixe o arquivo que termina em **`_x64-setup.exe`**, por exemplo
   `Cofre-de-Contas_0.1.0_x64-setup.exe`, e o **`SHA256SUMS.txt`**.
   - Existe também um `.msi` (`Cofre-de-Contas_0.1.0_x64_en-US.msi`), que instala para **todos os
     usuários** do computador e pede senha de administrador. Para uso pessoal, prefira o
     `-setup.exe`.
   - **Versões beta:** os nomes levam a versão completa
     (`Cofre-de-Contas_0.1.0-beta.4_x64-setup.exe` e `Cofre-de-Contas_0.1.0-beta.4_x64_en-US.msi`);
     a forma numérica do Windows Installer (`0.1.0.4`) fica só nos metadados do `.msi`.
   - A `v0.1.0-beta.1` é uma exceção: foi publicada antes da automação, como um ZIP
     (`instaladores-<commit>.zip`) que contém os instaladores com o nome gerado pelo Tauri
     (`Cofre de Contas_0.1.0_x64-setup.exe`, com espaços). A partir da próxima versão os arquivos
     ficam soltos na release, com os nomes acima.
3. **Confira se o arquivo é autêntico** (recomendado num gerenciador de senhas). Os nomes no
   `SHA256SUMS.txt` são exatamente os nomes dos arquivos da release. No PowerShell, na pasta
   Downloads, rode:
   ```powershell
   Get-FileHash .\Cofre-de-Contas_0.1.0_x64-setup.exe -Algorithm SHA256
   Get-Content .\SHA256SUMS.txt
   ```
   O código mostrado precisa ser **igual** ao da linha desse arquivo no `SHA256SUMS.txt` (ou ao
   hash escrito nas notas da release). Se for diferente, **não instale**. Em Linux/macOS:
   `sha256sum -c SHA256SUMS.txt` na pasta com os arquivos.
   - O hash confere a **integridade**: o arquivo que você baixou é idêntico ao que gerou aquele
     hash. Mas **sozinho não prova quem o publicou**: quem consegue trocar o instalador também
     consegue trocar o texto ao lado dele.
   - Releases geradas pelo workflow `Release` trazem também uma **attestation de proveniência**
     do GitHub: evidência de que o arquivo foi compilado neste repositório, a partir de um commit
     específico. Para conferir (precisa do [GitHub CLI](https://cli.github.com/)):
     ```powershell
     gh attestation verify .\Cofre-de-Contas_0.1.0_x64-setup.exe --repo juniorrafaels/cofre-de-senhas
     ```
     A `v0.1.0-beta.1` foi publicada antes desse workflow e **não tem attestation**.
   - Nada disso substitui uma **assinatura digital** do instalador, que ainda não existe, nem uma
     auditoria de segurança independente.
4. Dê dois cliques no instalador.
   - O instalador ainda **não é assinado digitalmente**, então o Windows pode mostrar
     **"O Windows protegeu o computador"**. Se o hash conferiu, clique em **Mais informações →
     Executar assim mesmo**.
5. Siga o instalador (Avançar → Instalar → Concluir). Ele não pede administrador.
6. Abra **Cofre de Contas** pelo **menu Iniciar**.

---

## Caminho 2: gerar o instalador a partir do código

Use este caminho se ainda não há uma release publicada, ou se você prefere compilar o app você
mesmo a partir do código que pode ler.

### 2.1 Instale as ferramentas (uma vez só)

Abra o **PowerShell** (menu Iniciar → digite "PowerShell") e rode, uma linha por vez:

```powershell
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Rustlang.Rustup -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

São o Node.js, a linguagem Rust e o compilador C++ da Microsoft. A instalação do compilador C++
demora e baixa alguns GB. **Reinicie o computador** no final.

> Sem `winget`? Instale manualmente: [Node.js LTS](https://nodejs.org),
> [Rust](https://rustup.rs) e [Build Tools for Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
> (marque **Desktop development with C++**).

### 2.2 Gere o instalador

1. Abra a pasta do projeto que você baixou. Se veio em ZIP, **extraia** primeiro: botão direito →
   *Extrair tudo*. Não rode de dentro do ZIP.
2. Dê dois cliques em **`Compilar instalador.bat`**.
3. O script confere se as ferramentas estão instaladas. Se faltar alguma, ele mostra o comando
   exato para instalar.
4. Depois ele compila o app. **A primeira vez demora de 5 a 15 minutos.**
5. No final, a pasta com o instalador abre sozinha, com o arquivo **`..._x64-setup.exe`**
   selecionado. Dê dois cliques nele e siga o instalador.
6. Abra **Cofre de Contas** pelo **menu Iniciar**.

> Dica: se a pasta do projeto estiver dentro do OneDrive ou do Dropbox, mova-a para fora antes
> (ex.: `C:\Projetos\cofre-de-senhas`). A compilação gera vários GB de arquivos temporários.

---

## Primeiros passos depois de instalar

1. **Crie a senha mestra.** Na primeira abertura aparece **"Criar senha mestra"**.
   - Use uma **frase longa** que você não usa em nenhum outro lugar (ex.: quatro ou mais palavras
     aleatórias).
   - **Ninguém consegue recuperar essa senha para você.** Não existe servidor nem "esqueci minha
     senha por e-mail".
2. **Gere a Recovery Key logo em seguida.** *Configurações → Segurança → Recovery Key → Gerar
   Recovery Key.*
   - É a única forma de recuperar o cofre se você esquecer a senha mestra.
   - **Imprima o kit de recuperação** (ou anote a chave no papel) e guarde longe do computador.
3. **Ajuste o bloqueio.** Em *Configurações → Segurança*, confira o tempo de bloqueio automático.
   Se quiser, ative "bloquear ao minimizar".
4. **Cadastre suas contas.** Organize por plataforma, projeto e etiqueta. Marque como sensíveis os
   campos personalizados que forem segredos (chaves de API, códigos).
5. **Faça backups.** *Configurações → Dados → Exportar backup.*
   - O arquivo `.vaultbackup` é criptografado com uma senha de backup que você escolhe.
   - Guarde cópias em outro lugar (pendrive, outro disco). Se o computador quebrar sem backup, os
     dados se perdem: o Cofre não sincroniza com a nuvem.

**Dicas de segurança:**
- Senhas copiadas pelo app são apagadas da área de transferência depois de alguns segundos e, no
  Windows, não entram no histórico do **Win+V**.
- Usuário e e-mail **não** ficam ocultos dentro do arquivo do cofre: só senhas, notas, dados de 2FA
  e campos sensíveis são criptografados. Detalhes em [SECURITY.md](../SECURITY.md).
- Nenhum gerenciador de senhas protege um computador com vírus. Mantenha o Windows atualizado.

---

## Atualizar, desinstalar e onde ficam os dados

**Atualizar:** baixe (ou compile) o instalador da versão nova e instale por cima. Seus dados são
mantidos. Antes, por segurança, exporte um backup.

**Desinstalar:** *Configurações do Windows → Aplicativos → Aplicativos instalados → Cofre de
Contas → Desinstalar.*
Desinstalar **não apaga** o seu cofre. Ele continua em:

| Item | Local |
|---|---|
| Cofre (banco de dados criptografado) | `%APPDATA%\com.rafaelcampos.cofredecontas\vault.db` |
| Imagens e avatares | `%APPDATA%\com.rafaelcampos.cofredecontas\images\` |

Para apagar tudo de vez, apague essa pasta depois de desinstalar. Faça isso só se tiver certeza.
Sem backup, os dados não voltam.

**Levar para outro computador:** instale o Cofre no PC novo e use *Configurações → Dados →
Restaurar backup* com o arquivo `.vaultbackup` e a senha do backup.

---

## Problemas comuns

| Problema | Solução |
|---|---|
| "O Windows protegeu o computador" | O instalador não é assinado. Confira o hash SHA-256 e clique em **Mais informações → Executar assim mesmo** |
| O app abre com a janela em branco | Instale o WebView2: `winget install --id Microsoft.EdgeWebView2Runtime -e` |
| `Compilar instalador.bat` diz que falta uma ferramenta | Rode o comando que ele mostrou, **feche e abra a janela de novo** (ou reinicie o PC) e tente outra vez |
| "cargo não é reconhecido" mesmo depois de instalar o Rust | Reinicie o computador. O script também procura o Rust em `%USERPROFILE%\.cargo\bin` sozinho |
| Esqueci a senha mestra | Na tela de desbloqueio, clique em **"Esqueci minha senha"** e use a Recovery Key. Sem ela, não há como recuperar |
