// O backend (Rust) continua retornando mensagens técnicas fixas em português — não internacionalizamos
// o backend (seção 13 do pedido de i18n). Este mapa faz o "menos invasivo" possível: casos
// conhecidos e diretamente exibidos ao usuário são traduzidos no frontend por correspondência
// exata da string; qualquer mensagem não mapeada (erros genéricos do SQLite, do sistema de
// arquivos etc.) passa direto, sem tradução — são técnicas por natureza.
const RAW_TO_KEY: Record<string, string> = {
  "O cofre está bloqueado.": "vaultLocked",
  "Senha incorreta.": "wrongPassword",
  "O cofre ainda não foi criado.": "vaultNotCreated",
  "A senha mestra deve ter pelo menos 8 caracteres.": "masterPasswordTooShort",
  "O cofre já foi criado.": "vaultAlreadyCreated",
  "A nova senha mestra deve ter pelo menos 8 caracteres.": "newMasterPasswordTooShort",
  "Não foi possível concluir a operação.": "genericOperationFailed",
  "Nenhuma Recovery Key foi configurada para este cofre.": "noRecoveryKeyConfigured",
  "Recovery Key incorreta.": "wrongRecoveryKey",
  "A pergunta não pode ficar vazia.": "securityQuestionEmpty",
  "A resposta não pode ficar vazia.": "securityAnswerEmpty",
  "Você atingiu o limite de 20 perguntas de segurança.": "securityQuestionLimit",
  "Pergunta não encontrada.": "securityQuestionNotFound",
  "Respostas insuficientes ou incorretas. Verifique e tente novamente.": "recoveryAnswersIncorrect",
  "Identidade confirmada.": "identityConfirmed",
  "Identidade ainda não confirmada.": "identityNotConfirmed",
  "Campo inválido para preservação.": "invalidPreserveField",
  "Conta não encontrada.": "accountNotFound",
  "Nenhuma senha cadastrada.": "noPasswordSet",
  "Não foi possível copiar para a área de transferência.": "clipboardCopyFailed",
  "não foi possível resolver o diretório de dados do app": "appDataDirUnresolved",
  "Nome de arquivo de imagem inválido.": "invalidImageFilename",
  "Não foi possível ler o arquivo de imagem.": "imageReadFailed",
  "Hash de imagem inválido.": "invalidImageHash",
  "Falha ao criptografar backup.": "backupEncryptFailed",
  "Arquivo de backup inválido.": "invalidBackupFile",
  "Senha de backup incorreta.": "wrongBackupPassword",
  "Senha de backup incorreta ou arquivo corrompido.": "wrongBackupPasswordOrCorrupt",
  "Desbloqueie o cofre antes de exportar um backup.": "unlockBeforeExport",
  "A senha do backup deve ter pelo menos 8 caracteres.": "backupPasswordTooShort",
  "Não foi possível ler o arquivo de backup.": "backupReadFailed",
  "As perguntas de segurança foram descontinuadas por motivos de segurança. Gere uma Recovery Key.": "securityQuestionsDeprecated",
  "Requisição de recuperação inválida.": "invalidRecoveryRequest",
  "Informe a senha mestra atual para restaurar um backup.": "importRequiresMasterPassword",
  "Selecione ao menos um tipo de caractere.": "pwgenSelectCharType",
  "A quantidade definida para um tipo não pode ser maior que o tamanho da senha.": "pwgenCountExceedsLength",
  "A soma das quantidades definidas não pode ultrapassar o tamanho total da senha.": "pwgenSumExceedsLength",
  "O tipo escolhido para começar a senha precisa estar habilitado.": "pwgenStartTypeDisabled",
  "O tipo escolhido para começar a senha precisa ter ao menos 1 caractere reservado.": "pwgenStartTypeNeedsCount",
  "O tipo escolhido para terminar a senha precisa estar habilitado.": "pwgenEndTypeDisabled",
  "O tipo escolhido para terminar a senha precisa ter ao menos 1 caractere reservado.": "pwgenEndTypeNeedsCount",
  "Para começar e terminar com o mesmo tipo, reserve pelo menos 2 caracteres dele.": "pwgenStartEndSameTypeNeedsTwo",
  "Falha ao distribuir os caracteres da senha.": "pwgenDistributionFailed",
  "Propriedade não encontrada.": "propertyNotFound",
  "Esta propriedade não é sensível.": "propertyNotSensitive",
  "Nome de tag inválido.": "invalidTagName",
  "Tema inválido.": "invalidTheme",
  "Valor booleano inválido.": "invalidBoolean",
  "Valor numérico inválido.": "invalidNumber",
  "Valor numérico fora do intervalo permitido.": "numberOutOfRange",
  "Modo de visualização inválido.": "invalidViewMode",
  "Escala de visualização inválida.": "invalidListScale",
  "Lista de colunas inválida.": "invalidColumnList",
  "Lista de colunas contém uma coluna desconhecida.": "unknownColumn",
  "Chave de configuração desconhecida.": "unknownSettingKey",
  "O valor da configuração excede o tamanho máximo permitido.": "valueTooLong",
  "Idioma inválido.": "invalidLanguage",
};

/**
 * Traduz uma mensagem de erro vinda do backend Rust (sempre em português) para o idioma ativo,
 * quando reconhecida. Mensagens desconhecidas (erros técnicos do SQLite, do sistema de arquivos
 * etc.) são retornadas como vieram — não há como traduzi-las com segurança, e são técnicas por
 * natureza (seção 13 do pedido de i18n).
 */
export function translateBackendError(t: (key: string, vars?: Record<string, string | number>) => string, raw: unknown): string {
  const message = String(raw);
  const key = RAW_TO_KEY[message];
  return key ? t(`errors.${key}`) : message;
}
