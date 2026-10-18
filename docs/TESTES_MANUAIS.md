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

### Perguntas de segurança (descontinuadas)
| # | Passo | Esperado | OK? |
|---|---|---|---|
| 19 | Configurações → Segurança → Perguntas de segurança | Aviso de recurso descontinuado; não há botão de adicionar nem de editar | |

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
