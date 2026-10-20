# Testes manuais do Cofre de Contas

Os testes automatizados (`cargo test`, `npm test`) cobrem a lógica com bancos em memória. Este
roteiro confere o que só aparece com o **app de verdade aberto no Windows**: área de
transferência, telas de backup e de recuperação, bloqueio.

> **Use somente dados fictícios.** Nunca faça estes testes no seu cofre real.

## 1. Preparar um cofre de teste isolado

O app instalado e o modo dev usam a mesma pasta de dados: `%APPDATA%\<identifier>\` (o
identifier está em `src-tauri/tauri.conf.json`). O script abaixo **renomeia** essa pasta para
guardar o cofre real e, no fim, devolve tudo como estava. Ele nunca apaga nada.

```powershell
# feche o Cofre de Contas antes
powershell -ExecutionPolicy Bypass -File scripts\cofre-teste-isolado.ps1 Preparar
```

Abra o app (instalador gerado por `npx tauri build`, em `src-tauri\target\release\bundle\`, ou
`npm run tauri dev`). Ele pedirá para criar um cofre novo.

**Dados de teste sugeridos:**
- senha mestra `Teste-Cofre-2026!`;
- uma conta `CONTA_TESTE` com senha `SENHA_TESTE_123`;
- uma propriedade sensível `CHAVE_TESTE_456`;
- uma propriedade **não** sensível.

## 2. Roteiro

Marque o resultado de cada item.

### Área de transferência (Windows)
Pré-requisito: *Configurações → Sistema → Área de transferência → Histórico* **ativado**.

| # | Passo | Esperado | OK? |
|---|---|---|---|
| 1 | Copie um texto qualquer no Bloco de Notas e abra o Win+V | O texto aparece no histórico | |
| 2 | No app, copie a senha da conta (cartão, lista e detalhe) e cole no Bloco de Notas | Cola normalmente | |
| 3 | Abra o Win+V | **Nenhuma** senha do app aparece; o texto do passo 1 continua lá | |
| 4 | Repita 2 e 3 com: propriedade sensível, senha do gerador, Recovery Key, botão de copiar no campo de senha do formulário | Nenhuma aparece no Win+V | |
| 5 | Copie o usuário ou e-mail de uma conta | **Aparece** no Win+V (esperado: não é segredo) | |
| 6 | Com "limpar área de transferência" ligado (ex.: 20 s), copie uma senha e espere o prazo | Colar depois do prazo não traz a senha | |
| 7 | Copie uma senha e, antes do prazo, copie outro texto seu | Seu texto **não** é apagado quando o prazo vence | |

### Backup
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 8 | Configurações → Dados → exportar backup com senha `Backup-Teste-1` | Gera o arquivo `.vaultbackup` | |
| 9 | Altere algo no cofre (ex.: apague a conta de teste) | — | |
| 10 | Importe o backup com a senha do backup certa e a **senha mestra errada** | Recusado; o cofre continua igual | |
| 11 | Importe com a senha mestra certa e a **senha do backup errada** | Recusado; o cofre continua igual | |
| 12 | Importe com as duas senhas certas | O cofre volta ao estado do passo 8; o app bloqueia e pede a senha mestra do backup | |

### Recovery Key e senha mestra
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 13 | Configurações → Segurança → gerar Recovery Key (anote a de teste) | A chave é exibida uma vez; o kit pode ser impresso | |
| 14 | Bloqueie o cofre, escolha "Esqueci minha senha" e use uma Recovery Key **errada** | Recusado | |
| 15 | Use a Recovery Key certa e defina a nova senha `Nova-Senha-Teste-2026!` | Entra no cofre; os dados estão intactos | |
| 16 | Bloqueie e tente a senha antiga | Recusada | |
| 17 | Desbloqueie com a senha nova | Entra | |
| 18 | Configurações → alterar senha mestra com a senha **atual errada** | Recusado | |

### Perguntas de segurança (opcional)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 19 | Configurações → Segurança → Perguntas de segurança | Aviso de riscos visível; botões "Adicionar pergunta", editar e remover | |
| 19a | Adicione 1 ou 2 perguntas (com a senha mestra) | Salva, mas a tela diz que a recuperação ainda NÃO funciona (mínimo 3) | |
| 19b | Adicione a 3ª pergunta, bloqueie e use "Esqueci a senha" | Exibe as perguntas; 3 respostas corretas permitem definir nova senha | |
| 19c | Tente adicionar/editar com senha mestra errada | Recusado, nada é salvo | |
| 19d | Remova todas as perguntas | Recurso desativado; "Esqueci a senha" não oferece perguntas | |

### Metadados cifrados (fase 1)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 19e | Abra um cofre antigo (com contas) e desbloqueie | Contas, usuários, e-mails e URLs aparecem normalmente; surge `vault.db.pre-v2.bak` ao lado do `vault.db` | |
| 19f | Crie e edite uma conta; busque por um trecho do usuário/e-mail/nome | A busca parcial acha a conta; a ordem alfabética por nome é a mesma de antes | |
| 19g | Feche o app e abra o `vault.db` num visualizador SQLite | Nome, usuário, e-mail, URLs, categoria e o detalhe do histórico aparecem como `enc:v2:...` | |
| 19h | Exporte um backup, restaure-o e desbloqueie | Tudo legível; nada de "ilegível" nas contas | |

### Segunda senha de recuperação (opcional)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 30 | Configurações → Segurança → "Segunda senha de recuperação" → Configurar (senha mestra atual + `Recuperacao-Teste-2026!`) | Aviso de guarda visível; indicador de força; status "Configurada em ..." | |
| 31 | Bloqueie e use "Esqueci minha senha" | Aparece a opção "Usar a segunda senha de recuperação" (junto com Recovery Key/perguntas, se houver) | |
| 32 | Use uma senha de recuperação **errada** | Mensagem "Segunda senha de recuperação incorreta."; nada muda | |
| 33 | Use a certa e defina a senha mestra nova | Entra com os dados intactos; a Recovery Key e as perguntas (se configuradas) continuam funcionando | |
| 34 | Configurações → Desativar (com a senha mestra) e repita o passo 31 | A opção desaparece | |

### Desbloqueio com duas senhas (opcional)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 35 | Configurações → Segurança → "Ativar duas senhas" | Mostra os riscos (perder uma senha); exige o aceite; valida tamanho, confirmação e senha 2 ≠ senha 1 | |
| 36 | Ative com a senha mestra atual + segunda senha de teste | Status "Ativado" | |
| 37 | Feche o app, abra de novo | A tela pede **Senha 1 e Senha 2** (a exigência vale após reiniciar) | |
| 38 | Digite só a senha 1, depois só a 2, depois as duas trocadas | Em nenhum caso abre; "Senha incorreta." sem dizer qual está errada | |
| 39 | Digite as duas certas | Abre; os dados estão intactos | |
| 40 | Alterar senha mestra / Recovery Key / perguntas / backup / excluir cofre | Cada formulário pede também a segunda senha atual | |
| 41 | Desative (as duas senhas atuais) e reinicie | Volta a pedir só uma senha | |
| 42 | Ative de novo, bloqueie e recupere por Recovery Key e redefina a senha | O cofre volta a uma senha só (aviso na tela); reative se quiser | |

### Bloqueio progressivo (opcional)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 43 | Configurações → Segurança → "Ativar bloqueio progressivo" (com a senha) | Texto mostra a tabela e os limites honestos; status "Ativado." | |
| 44 | Bloqueie e erre a senha 1 vez | Mensagem de senha incorreta e bloqueio de 15 s com contagem regressiva; botão desabilitado | |
| 45 | Durante o bloqueio, feche e reabra o app | O tempo restante continua (não reinicia) | |
| 46 | Durante o bloqueio, digite a senha CERTA | Não abre (a tentativa nem é verificada) | |
| 47 | Espere acabar, erre de novo | Espera de 30 s; depois 1 min, 5 min... (use o relógio com cuidado; não é preciso chegar a 4 h) | |
| 48 | Acerte a senha depois do prazo | Abre e a sequência zera (erre 1 vez: volta a 15 s) | |
| 49 | Abra duas janelas/instâncias do app e erre numa | A outra mostra o mesmo bloqueio | |
| 50 | Desative o bloqueio progressivo (senha) | O contador deixa de valer | |

### Um cofre aberto por vez
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 51 | Com o cofre aberto, inicie **uma segunda instância** do app (outro atalho/`.exe`) | A segunda mostra "já existe um cofre aberto"; campos e botão desabilitados | |
| 52 | Na segunda, use "Esqueci minha senha" com uma Recovery Key correta | Também recusado ("já existe um cofre aberto") | |
| 53 | Bloqueie o cofre na primeira instância | Em até ~3 s a segunda é liberada e consegue desbloquear | |
| 54 | Com o cofre aberto, encerre o processo à força (Gerenciador de Tarefas) e abra o app | Abre normalmente: não fica "preso" por lock obsoleto | |
| 55 | Suspenda/hiberne o PC com o cofre aberto em outra instância e volte | O lock continua com o dono; a segunda continua recusada até o primeiro bloquear/fechar | |

### Datas da conta
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 56 | Edite uma conta e preencha "Último login" | A data aparece na ficha e (se a coluna estiver ligada) na lista; "cadastro" e "edição" não mudam | |
| 57 | Abra e edite uma conta sem marcar como atualizada | Nenhum selo "Atualizada" aparece | |
| 58 | Na ficha, "Marcar como atualizada" | Selo aparece com a data e os dias restantes; o último login não muda | |
| 59 | Configurações → Aparência → desligue "Exibir o selo" | O selo some; religue e ele volta (nenhum dado muda) | |
| 60 | Em Aparência → colunas, ligue/desligue "Último login" | A coluna aparece/some na lista | |
| 61 | Cadastro/edição: digite uma senha na conta | O indicador (muito fraca…muito forte) muda a cada tecla; salvar uma senha fraca continua permitido | |

### Bloqueio
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 20 | Com o cofre aberto, pressione Win+L e volte | O cofre está bloqueado | |
| 21 | Com o cofre aberto, suspenda o PC e volte | O cofre está bloqueado | |
| 22 | Ajuste o bloqueio automático para 1 min e espere sem mexer | O cofre bloqueia | |

## 3. Restaurar o cofre real

```powershell
# feche o Cofre de Contas antes
powershell -ExecutionPolicy Bypass -File scripts\cofre-teste-isolado.ps1 Restaurar
```

O cofre de teste fica guardado como `<identifier>.TESTE-descartado-<data>`. Apague essa pasta
quando quiser. Para conferir a situação a qualquer momento:
`scripts\cofre-teste-isolado.ps1 Status`.
