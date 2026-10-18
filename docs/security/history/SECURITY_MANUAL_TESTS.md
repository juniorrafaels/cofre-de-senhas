> **Aviso: documento histórico de autoavaliação interna.**
> Este relatório foi produzido **durante o desenvolvimento** do Cofre de Contas como uma
> **autoavaliação interna** (revisão feita pelo próprio processo de desenvolvimento, com auxílio de
> ferramentas de IA). **Não é uma auditoria de segurança independente** nem uma certificação.
> Ele descreve o código **na data indicada no próprio documento** e **pode estar desatualizado** em
> relação ao código atual: achados, nomes de commands, contagens de testes e classificações podem
> ter mudado depois. O status de segurança atual está em
> [`SECURITY.md`](../../../SECURITY.md). Caminhos locais e informações do ambiente do
> desenvolvedor foram removidos desta cópia; marcadores `SECURITY_TEST_*`/`XSS_TEST_*` são dados
> sintéticos de teste.
>
> **Desatualizações conhecidas:**
> - Checklist acumulado até a data da validação final (2026-08-29). Ele não cobre funcionalidades
>   adicionadas depois e não reflete se os itens foram executados.
> - O caminho `src-tauri/target/release/` pode ser outro se houver um `target-dir` personalizado
>   do Cargo. Use o caminho que o `npm run tauri build` mostrar.
> - O item 16 chama de propósito commands removidos (`decrypt_secret` etc.) para confirmar que eles
>   não existem mais.
> - O checklist ainda não tem itens para os problemas encontrados na revisão posterior (ver último
>   item).
> - Uma revisão posterior, feita antes da publicação, encontrou problemas que **não** aparecem
>   nestes relatórios e que estão sendo tratados: (1) as **perguntas de segurança** permitem força
>   bruta offline **resposta por resposta** (cada resposta protege seu próprio *share* e pode ser
>   testada isoladamente contra o `vault.db`, então o limiar 3-de-N não multiplica o custo);
>   (2) **`import_backup` roda sem autenticação** (não exige cofre desbloqueado nem senha mestra) e
>   substitui o cofre inteiro; (3) **`reset_master_password_after_recovery`** só verifica se há
>   uma DEK em memória, então pode ser chamado a partir de uma **sessão normal desbloqueada** para
>   trocar a senha mestra sem informar a atual; (4) segredos copiados vão para a área de
>   transferência do Windows sem serem excluídos do **histórico do clipboard (Win+V)** e da
>   sincronização em nuvem, então a limpeza automática não remove essas cópias.

# Testes Manuais Pendentes — Cofre de Contas

Estes testes exigem um Windows real com sessão gráfica interativa e (em alguns casos) hardware
específico (notebook com tampa, suporte a hibernação). Nenhum deles foi simulado nem seu
resultado inventado nas auditorias anteriores — execute-os você mesmo antes de confiar dados
reais ao aplicativo, especialmente os marcados como **crítico**.

Contexto necessário antes de começar: compile e rode o app em modo produção para testar o
comportamento real (`npm run tauri build`, depois abra o executável gerado em
`src-tauri/target/release/`) — o modo `npm run tauri dev` também serve para os testes de
lock/suspend, mas é o build de produção que valida o item "DevTools indisponível".

---

## 1. Win + L bloqueia o cofre — **crítico**

Por quê: a Fase 3 adicionou um hook nativo (`native_lock.rs`) que deveria chamar
`VaultState::clear()` assim que o Windows bloqueia a sessão (evento `WM_WTSSESSION_CHANGE` /
`WTS_SESSION_LOCK`). Isso nunca foi testado com um Win+L real.

```
[ ] 1. Abra o app, crie ou desbloqueie um cofre existente.
[ ] 2. Confirme que está na tela principal (cofre desbloqueado).
[ ] 3. Pressione Win + L (bloqueia a sessão do Windows).
[ ] 4. Aguarde alguns segundos, depois faça login novamente no Windows.
[ ] 5. Volte para a janela do app.

Resultado esperado: a tela de "Desbloquear cofre" deve aparecer — ou seja, o cofre foi
bloqueado automaticamente durante o Win+L, não apenas quando você voltar o foco para a janela.

Se o cofre AINDA aparecer desbloqueado ao voltar: o hook nativo não disparou nesta máquina
(pode acontecer em versões antigas do Windows ou em configurações incomuns). Nesse caso, o
auto-lock por relógio de parede (Fase 2) ainda deve bloquear assim que o tempo configurado em
Configurações > "Bloquear automaticamente após" tiver passado — teste também o item 8 abaixo
para confirmar que pelo menos essa rede de segurança funciona.
```

## 2. Suspend (suspender/sleep) bloqueia o cofre — **crítico**

```
[ ] 1. Desbloqueie o cofre.
[ ] 2. Suspenda a máquina (menu Iniciar > Energia > Suspender, ou feche a tampa se notebook
       e a suspensão estiver configurada para isso).
[ ] 3. Aguarde pelo menos 10-15 segundos antes de retomar (para dar tempo do SO processar o
       evento de suspensão de verdade).
[ ] 4. Retome a máquina (mova o mouse / pressione uma tecla / abra a tampa).
[ ] 5. Volte para a janela do app.

Resultado esperado: tela de "Desbloquear cofre".
```

## 3. Hibernar bloqueia o cofre

Só aplicável se hibernação estiver habilitada no seu Windows (`powercfg /a` no PowerShell/CMD
mostra os estados disponíveis).

```
[ ] 1. Desbloqueie o cofre.
[ ] 2. Hiberne a máquina.
[ ] 3. Ligue novamente e faça login no Windows.
[ ] 4. Volte para a janela do app.

Resultado esperado: tela de "Desbloquear cofre".
```

## 4. Fechar a tampa (notebook) bloqueia o cofre

Só aplicável se você estiver testando num notebook.

```
[ ] 1. Desbloqueie o cofre.
[ ] 2. Verifique em Configurações de Energia do Windows o que "fechar a tampa" faz
       (normalmente = suspender).
[ ] 3. Feche a tampa, aguarde alguns segundos, abra novamente.
[ ] 4. Faça login no Windows se pedido.
[ ] 5. Volte para a janela do app.

Resultado esperado: tela de "Desbloquear cofre".
```

## 5. Lock-on-minimize — desativado (comportamento padrão)

```
[ ] 1. Em Configurações do app, confirme que "Bloquear ao minimizar" está DESLIGADO.
[ ] 2. Desbloqueie o cofre.
[ ] 3. Minimize a janela do app.
[ ] 4. Restaure a janela.

Resultado esperado: o cofre continua desbloqueado (minimizar sozinho não bloqueia).
```

## 6. Lock-on-minimize — ativado

```
[ ] 1. Em Configurações do app, LIGUE "Bloquear ao minimizar".
[ ] 2. Desbloqueie o cofre.
[ ] 3. Minimize a janela.
[ ] 4. Restaure a janela imediatamente.

Resultado esperado: tela de "Desbloquear cofre" já deve aparecer assim que a janela é
restaurada (o bloqueio acontece no instante em que a janela fica oculta, não quando você volta).
```

## 7. Auto-lock por inatividade

```
[ ] 1. Em Configurações, defina "Bloquear automaticamente após" para o menor valor disponível
       (ex.: 1 minuto).
[ ] 2. Desbloqueie o cofre.
[ ] 3. Não toque no mouse/teclado pelo tempo configurado + 10 segundos de margem.

Resultado esperado: tela de "Desbloquear cofre" aparece sozinha, sem você precisar interagir.

[ ] 4. Repita, mas desta vez mexa o mouse pouco antes do tempo expirar — confirme que o timer
       reinicia (ou seja, o cofre NÃO bloqueia enquanto você está ativo).
```

## 8. Auto-lock sobrevive a uma suspensão curta (backstop do relógio de parede)

Este teste confirma a mitigação da Fase 2 que continua ativa mesmo se o hook nativo (item 1/2)
falhar nesta máquina.

```
[ ] 1. Configure "Bloquear automaticamente após" para 1 minuto.
[ ] 2. Desbloqueie o cofre.
[ ] 3. Suspenda a máquina por MAIS de 1 minuto (ex.: 3 minutos) e retome.

Resultado esperado: tela de "Desbloquear cofre" (o app deve perceber, ao voltar o foco, que
mais tempo se passou do que o configurado, mesmo que o `setTimeout` do JS não tenha "corrido"
durante a suspensão).
```

## 9. DevTools indisponível em produção

```
[ ] 1. Rode `npm run tauri build` (ou `cargo build --release` dentro de `src-tauri/`).
[ ] 2. Abra o executável gerado (não o `npm run tauri dev`).
[ ] 3. Tente abrir o DevTools: tecle F12, e também clique com o botão direito em qualquer
       lugar da janela e procure "Inspecionar"/"Inspect".

Resultado esperado: nada deve acontecer — sem F12, sem opção de "Inspecionar" no menu de
contexto (ou o menu de contexto padrão do WebView2 nem aparece).

[ ] 4. Para comparação, repita com `npm run tauri dev` — aí SIM o DevTools deve abrir
       normalmente (comportamento esperado em desenvolvimento).
```

## 10. Clipboard limpa automaticamente

```
[ ] 1. Em Configurações, confirme que "Limpar clipboard automaticamente" está ligado, com um
       tempo curto (ex.: 10-20 segundos) para o teste.
[ ] 2. Copie a senha de uma conta (ícone de copiar).
[ ] 3. Cole em qualquer editor de texto para confirmar que copiou.
[ ] 4. Aguarde o tempo configurado + alguns segundos.
[ ] 5. Tente colar novamente em outro lugar.

Resultado esperado: a área de transferência deve estar vazia (ou conter outra coisa, se você
copiou algo diferente nesse meio-tempo) — não deve mais colar a senha.

[ ] 6. Repita os passos 2-3, mas desta vez copie outro texto qualquer (de fora do app) DEPOIS
       de copiar a senha, antes do timer expirar.

Resultado esperado: quando o timer da senha expirar, ele NÃO deve apagar o texto novo que você
colou por cima — a limpeza só remove a área de transferência se ela ainda contiver exatamente
o valor que o app copiou.
```

## 11. Encerrar o app libera a DEK

```
[ ] 1. Desbloqueie o cofre.
[ ] 2. Feche o aplicativo completamente (não apenas minimizar).
[ ] 3. Abra novamente.

Resultado esperado: o app deve pedir a senha mestra novamente (nunca deve "lembrar" que
estava desbloqueado entre execuções diferentes do processo).
```

## 12. Ciclo completo de backup (exportar/importar)

Não é específico da Fase 3, mas continua sem cobertura de teste manual — recomendado repetir
periodicamente após qualquer mudança de schema:

```
[ ] 1. Com o cofre desbloqueado e pelo menos uma conta/projeto/tag/pergunta de segurança
       cadastrados, exporte um backup com uma senha de sua escolha.
[ ] 2. Crie um cofre novo (ou anote que vai sobrescrever o atual) e importe o backup com a
       mesma senha.
[ ] 3. Confirme visualmente que todas as contas, projetos, tags, perguntas de segurança e
       Recovery Key (se configurada) aparecem exatamente como antes.
[ ] 4. Tente importar o mesmo arquivo com uma senha ERRADA — deve ser rejeitado com uma
       mensagem de erro genérica, sem alterar o cofre atual.
```

---

# Fase 4 — testes manuais pendentes (ver SECURITY_AUDIT_PHASE_4.md)

Este ambiente tem desktop real (o app foi compilado e iniciado com sucesso via `npm run tauri
dev` durante a Fase 4 — processo confirmado rodando, sem erro no console), mas **não há um driver
de UI configurado** para este projeto (Tauri não tem um equivalente pronto ao Playwright para
Electron; exigiria configurar `tauri-driver` + `msedgedriver` do zero, fora do escopo desta
sessão). Por isso, os itens abaixo — que dependem de clicar/digitar na janela real ou abrir o
DevTools — não puderam ser executados nesta sessão e ficam como manuais, com prioridade **alta**
por serem a validação final da mudança arquitetural desta fase.

## 13. Fluxos normais de conta/propriedade — crítico

```
[ ] 1. Criar uma conta com senha, notes e 2FA (todos os métodos). Salvar.
[ ] 2. Reabrir a conta: confirmar que senha (via "Mostrar"), notes e os campos de 2FA aparecem
       corretos.
[ ] 3. Editar a conta SEM tocar na senha — confirmar que a senha antiga continua funcionando
       (não foi apagada por engano pela lógica de "manter senha atual").
[ ] 4. Editar a conta trocando a senha — confirmar que a senha nova é a que passa a valer.
[ ] 5. Copiar a senha pelo card/lista (sem abrir o detalhe) — colar em outro app, confirmar que é
       a senha certa.
[ ] 6. Criar uma propriedade sensível (ex.: "Chave de API"), revelar, copiar, editar, excluir.
[ ] 7. Criar uma propriedade NÃO sensível — confirmar que aparece em texto puro na lista sem
       precisar "revelar".

Resultado esperado: nenhuma regressão de comportamento em relação ao que existia antes da Fase 4
— só muda o que viaja por IPC, não a experiência do usuário.
```

## 14. Rate limiter de "revelar" — alta prioridade

```
[ ] 1. Com várias contas cadastradas (15+), abra o detalhe de cada uma e clique em "Mostrar
       senha" rapidamente, uma após a outra (o mais rápido que conseguir clicar).
[ ] 2. Depois de ~25 revelações em poucos segundos, a próxima deve falhar com "Muitas revelações
       em pouco tempo. Aguarde alguns segundos e tente novamente."
[ ] 3. Aguarde ~10 segundos sem revelar nada, tente de novo — deve funcionar normalmente.
[ ] 4. Confirme que COPIAR senha (sem revelar) não é afetado mesmo copiando várias contas em
       sequência rápida — o limite só se aplica a "revelar" (mostrar na tela).

Resultado esperado: uso normal (revelar uma senha de vez em quando) nunca é afetado; um clique
automatizado/script em massa é throttled depois de ~25 chamadas em 10 segundos.
```

## 15. Reautenticação em Recovery Key / perguntas de segurança — crítico

```
[ ] 1. Em Configurações > Recovery Key, clique em "Gerar Recovery Key" — confirme que agora pede
       a senha mestra antes de gerar.
[ ] 2. Digite a senha ERRADA — confirme que é rejeitado e a chave NÃO é gerada/trocada.
[ ] 3. Digite a senha certa — confirme que a chave é gerada normalmente.
[ ] 4. Repita para "Desativar" Recovery Key.
[ ] 5. Em "Perguntas de segurança", adicione uma pergunta nova pedindo a senha mestra no próprio
       formulário — confirme que senha errada bloqueia a gravação.
[ ] 6. Edite uma pergunta existente e exclua uma pergunta — confirme que ambas também pedem a
       senha mestra e a rejeitam se errada.

Resultado esperado: nenhuma dessas 5 ações (gerar/desativar Recovery Key; adicionar/editar/
excluir pergunta) deve completar sem a senha mestra correta, mesmo que a WebView tente chamar o
command diretamente (a validação é no Rust, não no formulário).
```

## 16. Simulação de XSS via DevTools (dump sintético) — crítico

Só disponível em `npm run tauri dev` (DevTools desabilitado em build release, por design — ver
Fase 3). Use exclusivamente **contas sintéticas** (ex.: nome "XSS_TEST_PASSWORD_A" com senha
`XSS_TEST_PASSWORD_A`), nunca dados reais, e remova-as ao final.

```
[ ] 1. Crie 2-3 contas sintéticas com senha, uma propriedade sensível e notes preenchidos.
[ ] 2. Abra o DevTools (F12) com o cofre desbloqueado. No console, rode:
       await window.__TAURI__.core.invoke('decrypt_secret', { ciphertext: 'qualquer' })
       Esperado: erro "unknown command" ou equivalente (o command não existe mais).
[ ] 3. Rode o mesmo para 'encrypt_secret' e 'copy_secret_to_clipboard' — mesmo resultado esperado.
[ ] 4. Liste as contas (`invoke('list_accounts_with_relations', { scope: 'all' })`) e confirme
       que o JSON retornado NÃO contém `encrypted_password`, `notes` nem `two_factor_*` — só
       `has_password` e metadados.
[ ] 5. Peça `reveal_account_password` para uma conta sintética por id — confirme que funciona
       (isso é esperado: a UI legítima também revela sob pedido).
[ ] 6. Em loop, chame `reveal_account_password` para MAIS de 25 ids em menos de 10s — confirme
       que em algum ponto passa a falhar com a mensagem do rate limiter (ver item 14).
[ ] 7. Tente `reveal_sensitive_property` passando o `property_id` de uma conta com o `account_id`
       de OUTRA conta sintética — confirme que é rejeitado com "Propriedade não encontrada."
[ ] 8. Tente `invoke('plugin:clipboard-manager|read_text')` diretamente — confirme que falha (a
       permissão foi removida da capability; a WebView não pode mais ler o clipboard).
[ ] 9. Tente `fetch('https://example.com', { method: 'POST', body: 'teste' })` — confirme que o
       DevTools mostra um erro de CSP (`Refused to connect...`) e a requisição não sai.
[ ] 10. Tente abrir uma URL com esquema perigoso: `invoke('plugin:opener|open_url', { url:
        'javascript:alert(1)' })` e depois com `'file:///C:/Windows/System32/cmd.exe'` —
        confirme que ambas são rejeitadas pela ACL do Tauri.
[ ] 11. Remova as contas sintéticas criadas no passo 1.

Resultado esperado (documentar exatamente o que passou/falhou, sem maquiagem): os passos 2-4, 7-10
devem falhar (bloqueados); o passo 5 funciona (esperado — é a mesma coisa que a UI legítima faz);
o passo 6 confirma que o rate limiter throttla, mas não impede, um dump completo dado tempo
suficiente. Se qualquer resultado for diferente do esperado, é um achado real a reportar, não a
esconder.
```
