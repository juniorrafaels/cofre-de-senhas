import { invoke } from "@tauri-apps/api/core";
import { openUrl as openUrlPlugin } from "@tauri-apps/plugin-opener";
import type { PasswordGeneratorOptions, RecoveryOutcome, RecoveryQuestion, SecurityQuestionsSummary } from "../types";
import { translate, useLocaleStore } from "../i18n";

const ALLOWED_URL_SCHEMES = new Set(["http:", "https:"]);

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
}

// `password2` / `currentPassword2`: segunda senha, só usada quando o cofre exige duas senhas para
// desbloquear (política aplicada no backend — a interface apenas coleta o campo extra).
export const vaultCommands = {
  status: () => invoke<VaultStatus>("vault_status"),
  create: (password: string) => invoke<void>("create_vault", { password }),
  unlock: (password: string, password2?: string) =>
    invoke<void>("unlock_vault", { password, password2: password2 || null }),
  lock: () => invoke<void>("lock_vault"),
  changeMasterPassword: (currentPassword: string, newPassword: string, currentPassword2?: string) =>
    invoke<void>("change_master_password", { currentPassword, newPassword, currentPassword2: currentPassword2 || null }),
  // Etapa 1 da exclusão do cofre: confere a senha mestra atual sem alterar nada — reaproveita a
  // mesma verificação real usada por change_master_password/Recovery Key/perguntas de segurança.
  verifyMasterPassword: (password: string, password2?: string) =>
    invoke<void>("verify_master_password", { password, password2: password2 || null }),
  // Etapa 2 já foi confirmada pela UI (usuário digitou "EXCLUIR") antes de chamar isto. O Rust
  // reautentica a senha mestra de novo aqui mesmo, então uma chamada direta sem a UI não
  // consegue pular a verificação.
  deleteVault: (password: string, password2?: string) =>
    invoke<void>("delete_vault", { password, password2: password2 || null }),
};

/** Estado público da tela de desbloqueio e das configurações de segurança (nada aqui é segredo). */
export interface UnlockGateStatus {
  initialized: boolean;
  unlocked: boolean;
  /** O desbloqueio exige duas senhas. */
  dual: boolean;
  throttle_enabled: boolean;
  locked: boolean;
  remaining_seconds: number;
  failed_count: number;
  /** Outra instância/janela do app já mantém um cofre desbloqueado. */
  open_elsewhere: boolean;
  recovery_password_enabled: boolean;
  /** Metadados de proteção ilegíveis/de versão desconhecida (não é erro de senha). */
  protection_corrupt: boolean;
}

// Política de desbloqueio e bloqueio progressivo. Tudo que ALTERA política reautentica as
// credenciais atuais dentro do próprio comando Rust.
export const unlockPolicyCommands = {
  gateStatus: () => invoke<UnlockGateStatus>("unlock_gate_status"),
  enableDual: (currentPassword: string, secondPassword: string) =>
    invoke<void>("enable_dual_unlock", { currentPassword, secondPassword }),
  disableDual: (currentPassword: string, currentPassword2: string) =>
    invoke<void>("disable_dual_unlock", { currentPassword, currentPassword2 }),
  changeSecond: (currentPassword: string, currentPassword2: string, newSecondPassword: string) =>
    invoke<void>("change_second_unlock_password", { currentPassword, currentPassword2, newSecondPassword }),
  setThrottle: (enabled: boolean, currentPassword: string, currentPassword2?: string) =>
    invoke<void>("set_unlock_throttle", { enabled, currentPassword, currentPassword2: currentPassword2 || null }),
};

export interface RecoveryPasswordStatus {
  enabled: boolean;
  created_at: string | null;
}

// Segunda senha de recuperação (opcional): um envelope independente da DEK.
export const recoveryPasswordCommands = {
  status: () => invoke<RecoveryPasswordStatus>("recovery_password_status"),
  set: (currentPassword: string, newRecoveryPassword: string, currentPassword2?: string) =>
    invoke<void>("set_recovery_password", { currentPassword, currentPassword2: currentPassword2 || null, newRecoveryPassword }),
  disable: (currentPassword: string, currentPassword2?: string) =>
    invoke<void>("disable_recovery_password", { currentPassword, currentPassword2: currentPassword2 || null }),
  unlock: (recoveryPassword: string) => invoke<void>("unlock_with_recovery_password", { recoveryPassword }),
};

// Fase 4 (SECURITY_AUDIT_PHASE_4.md): não existe mais `encrypt_secret`/`decrypt_secret` — nenhum
// command aceita ciphertext arbitrário da WebView. Cada segredo tem sua própria operação
// específica por ID (a Rust busca o ciphertext ela mesma no SQLite antes de cifrar/decifrar).
export const clipboardCommands = {
  copy: (text: string, clearAfterSeconds?: number) =>
    invoke<void>("copy_to_clipboard", { text, clearAfterSeconds: clearAfterSeconds ?? null }),
  // Para segredos que já estão na WebView por natureza (senha recém-gerada, Recovery Key exibida
  // uma única vez): no Windows, o Rust marca o conteúdo para não entrar no Histórico (Win+V) nem
  // na sincronização em nuvem da área de transferência.
  copySecret: (text: string, clearAfterSeconds?: number) =>
    invoke<void>("copy_to_clipboard", { text, clearAfterSeconds: clearAfterSeconds ?? null, sensitive: true }),
};

export interface TwoFactorDetails {
  phone: string;
  email: string;
  app: string;
  notes: string;
}

// Senha e observações de uma conta: revelar/copiar/ler sempre por `id`, nunca por ciphertext.
export const accountSecretCommands = {
  revealPassword: (id: number) => invoke<string>("reveal_account_password", { id }),
  copyPassword: (id: number, clearAfterSeconds?: number) =>
    invoke<void>("copy_account_password", { id, clearAfterSeconds: clearAfterSeconds ?? null }),
  getNotes: (id: number) => invoke<string>("get_account_notes", { id }),
  getTwoFactorDetails: (id: number) => invoke<TwoFactorDetails>("get_account_two_factor_details", { id }),
};

// Propriedades sensíveis: revelar/copiar sempre por (accountId, propertyId) — o Rust confirma
// posse (a propriedade pertence a essa conta) antes de decifrar qualquer coisa.
export const propertySecretCommands = {
  reveal: (accountId: number, propertyId: number) =>
    invoke<string>("reveal_sensitive_property", { accountId, propertyId }),
  copy: (accountId: number, propertyId: number, clearAfterSeconds?: number) =>
    invoke<void>("copy_sensitive_property", { accountId, propertyId, clearAfterSeconds: clearAfterSeconds ?? null }),
};

export const backupCommands = {
  export: (outPath: string, backupPassword: string) =>
    invoke<void>("export_backup", { outPath, backupPassword }),
  // Restaurar substitui o cofre inteiro: se já existe um cofre, o Rust exige e verifica a senha
  // mestra ATUAL antes de abrir o arquivo (numa instalação sem cofre ela é opcional).
  import: (inPath: string, backupPassword: string, currentMasterPassword?: string, currentMasterPassword2?: string) =>
    invoke<void>("import_backup", {
      inPath,
      backupPassword,
      currentMasterPassword: currentMasterPassword || null,
      currentMasterPassword2: currentMasterPassword2 || null,
    }),
};

// Defesa em profundidade (Fase 2): a capability `opener:allow-open-url` do Tauri já restringe
// o plugin a esquemas http(s) via ACL nativo, mas validamos aqui também para: (1) dar um erro
// claro em vez de uma rejeição silenciosa do plugin, e (2) não depender só da configuração do
// backend caso ela mude no futuro. Bloqueia `javascript:`, `data:`, `file:` e qualquer esquema
// que não seja http/https.
//
// ESPELHA `validate::http_url_optional` (src-tauri/src/validate.rs). Os dois são testados com os
// mesmos casos (test-fixtures/external-urls.json); ao mudar um, mude o outro. O plugin opener
// compara a string CRUA com o escopo (sensível a maiúsculas) e a entrega crua ao sistema, então
// aqui também não passa nada que um parser aceite e o shell interprete diferente.
const DECEPTIVE_URL_CHARS =
  /[\u0000-\u001F\u007F-\u009F\s\\\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]|[\u{E0000}-\u{E007F}]/u;

export function isAllowedExternalUrl(url: string): boolean {
  // Controles, espaços, barra invertida e caracteres invisíveis/bidi (U+202E...) nunca passam.
  if (DECEPTIVE_URL_CHARS.test(url)) return false;
  // Exige `http(s)://` literal seguido de host: o parser WHATWG aceita `https:host` e `http:///x`.
  const match = /^https?:\/\/([^/?#]*)/i.exec(url);
  if (!match || match[1] === "" || match[1].includes("@")) return false; // sem usuário/senha
  try {
    const parsed = new URL(url);
    return ALLOWED_URL_SCHEMES.has(parsed.protocol) && parsed.hostname !== "";
  } catch {
    return false;
  }
}

// O plugin opener casa a string crua com `https://**` (sensível a maiúsculas): `HTTPS://x` seria
// negado. Só o esquema muda de caixa; o resto da URL vai exatamente como foi salvo.
export function normalizeExternalUrl(url: string): string {
  return url.replace(/^https?(?=:\/\/)/i, (scheme) => scheme.toLowerCase());
}

export async function openLoginUrl(url: string) {
  if (!url) return;
  if (!isAllowedExternalUrl(url)) {
    throw new Error(translate(useLocaleStore.getState().locale, "errors.invalidUrlScheme"));
  }
  await openUrlPlugin(normalizeExternalUrl(url));
}

// Perguntas de segurança (recurso opcional): adicionar/editar/remover exige a senha mestra atual,
// reverificada no próprio comando Rust (não um flag do frontend) — essas ações alteram um dos
// mecanismos de recuperação do cofre.
export const securityQuestionCommands = {
  summary: () => invoke<SecurityQuestionsSummary>("security_questions_summary"),
  add: (currentPassword: string, question: string, answer: string, currentPassword2?: string) =>
    invoke<void>("add_security_question", { currentPassword, question, answer, currentPassword2: currentPassword2 || null }),
  update: (currentPassword: string, id: number, question: string, answer?: string, currentPassword2?: string) =>
    invoke<void>("update_security_question", {
      currentPassword,
      id,
      question,
      answer: answer || null,
      currentPassword2: currentPassword2 || null,
    }),
  remove: (currentPassword: string, id: number, currentPassword2?: string) =>
    invoke<void>("delete_security_question", { currentPassword, id, currentPassword2: currentPassword2 || null }),
  getRecoveryQuestions: () => invoke<RecoveryQuestion[]>("get_recovery_questions"),
  attemptRecovery: (answers: { id: number; answer: string }[]) =>
    invoke<RecoveryOutcome>("attempt_vault_recovery", { answers }),
  resetPasswordAfterRecovery: (newPassword: string) =>
    invoke<void>("reset_master_password_after_recovery", { newPassword }),
};

export interface RecoveryKeyStatus {
  enabled: boolean;
  created_at: string | null;
}

// Fase 4: gerar/desativar a Recovery Key também exige a senha mestra atual, reverificada no Rust.
export const recoveryKeyCommands = {
  status: () => invoke<RecoveryKeyStatus>("recovery_key_status"),
  // Retorna a chave em texto puro UMA VEZ — o chamador deve exibi-la, deixar o usuário copiar/
  // imprimir, e nunca persisti-la (nem em localStorage) além do tempo de exibição.
  generate: (currentPassword: string, currentPassword2?: string) =>
    invoke<string>("generate_recovery_key", { currentPassword, currentPassword2: currentPassword2 || null }),
  disable: (currentPassword: string, currentPassword2?: string) =>
    invoke<void>("disable_recovery_key", { currentPassword, currentPassword2: currentPassword2 || null }),
  unlockWithKey: (recoveryKey: string) => invoke<void>("unlock_with_recovery_key", { recoveryKey }),
};

// Gerador de senhas (Configurações → Gerador de Senhas): a geração roda inteiramente no backend
// com o CSPRNG do SO (ver src-tauri/src/commands/password_generator.rs) — o frontend nunca usa
// Math.random() nem gera nada localmente, e a senha resultante não é salva em nenhum lugar aqui.
export const passwordGeneratorCommands = {
  generate: (options: PasswordGeneratorOptions) => invoke<string>("generate_password", { options }),
};
