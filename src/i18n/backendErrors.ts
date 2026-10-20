// O backend (Rust) continua retornando mensagens técnicas fixas em português — não internacionalizamos
// o backend (seção 13 do pedido de i18n). Este mapa faz o "menos invasivo" possível: casos
// conhecidos e diretamente exibidos ao usuário são traduzidos no frontend por correspondência
// exata da string; qualquer mensagem não mapeada (erros genéricos do SQLite, do sistema de
// arquivos etc.) passa direto, sem tradução — são técnicas por natureza.
import { formatWait } from "../lib/duration";

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
  "A pergunta é longa demais.": "securityQuestionTooLong",
  "A resposta é longa demais.": "securityAnswerTooLong",
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
  // Mensagens de `validate::http_url_optional` (o texto exato é conferido por um teste contra validate.rs).
  "A URL de login deve ser um endereço completo começando com https:// (ou http://), sem espaços, barras invertidas, usuário/senha ou caracteres invisíveis.": "invalidLoginUrl",
  "A URL do site deve ser um endereço completo começando com https:// (ou http://), sem espaços, barras invertidas, usuário/senha ou caracteres invisíveis.": "invalidWebsiteUrl",
  "Os dados de proteção do cofre estão corrompidos ou usam um formato não suportado.": "protectionCorrupt",
  "O desbloqueio com duas senhas já está ativado.": "dualAlreadyOn",
  "O desbloqueio com duas senhas não está ativado.": "dualNotOn",
  "A segunda senha precisa ser diferente da primeira.": "secondSameAsFirst",
  "A segunda senha deve ter pelo menos 8 caracteres.": "secondTooShort",
  "A senha é longa demais.": "passwordTooLong",
  "Nenhuma segunda senha de recuperação foi configurada para este cofre.": "recoveryPwNotConfigured",
  "Segunda senha de recuperação incorreta.": "recoveryPwWrong",
  "Os dados da segunda senha de recuperação estão corrompidos.": "recoveryPwCorrupt",
  "A segunda senha de recuperação deve ter pelo menos 8 caracteres.": "recoveryPwTooShort",
  "A senha de recuperação precisa ser diferente das senhas de desbloqueio.": "recoveryPwSameAsUnlock",
  "A data do último login não pode estar no futuro.": "lastLoginFuture",
  "A data do último login é inválida.": "lastLoginInvalid",
  "Não foi possível garantir a exclusividade do cofre aberto (arquivo de controle indisponível).": "exclusivityUnavailable",
};

// Erros ESTRUTURADOS do backend: códigos estáveis (não mensagens) para o que a interface precisa
// reagir de forma especial — `E_LOCKED:<segundos>:<falhas>`, `E_VAULT_OPEN_ELSEWHERE` e
// `E_SECOND_PASSWORD_REQUIRED`.
export type StructuredBackendError =
  | { code: "locked"; seconds: number; failures: number }
  | { code: "vault_open_elsewhere" }
  | { code: "second_password_required" };

export function parseStructuredError(raw: unknown): StructuredBackendError | null {
  const message = String(raw).trim();
  const locked = /^E_LOCKED:(\d+):(\d+)$/.exec(message);
  if (locked) return { code: "locked", seconds: Number(locked[1]), failures: Number(locked[2]) };
  if (message === "E_VAULT_OPEN_ELSEWHERE") return { code: "vault_open_elsewhere" };
  if (message === "E_SECOND_PASSWORD_REQUIRED") return { code: "second_password_required" };
  return null;
}

/**
 * Traduz uma mensagem de erro vinda do backend Rust (sempre em português) para o idioma ativo,
 * quando reconhecida. Mensagens desconhecidas (erros técnicos do SQLite, do sistema de arquivos
 * etc.) são retornadas como vieram — não há como traduzi-las com segurança, e são técnicas por
 * natureza (seção 13 do pedido de i18n).
 */
export function translateBackendError(t: (key: string, vars?: Record<string, string | number>) => string, raw: unknown): string {
  const message = String(raw);
  const structured = parseStructuredError(message);
  if (structured) {
    switch (structured.code) {
      case "locked":
        return t("errors.locked", { time: formatWait(structured.seconds) });
      case "vault_open_elsewhere":
        return t("errors.vaultOpenElsewhere");
      case "second_password_required":
        return t("errors.secondPasswordRequired");
    }
  }
  const key = RAW_TO_KEY[message];
  return key ? t(`errors.${key}`) : message;
}
