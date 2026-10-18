import { invoke } from "@tauri-apps/api/core";
import { openUrl as openUrlPlugin } from "@tauri-apps/plugin-opener";
import type { PasswordGeneratorOptions, RecoveryOutcome, RecoveryQuestion, SecurityQuestionsSummary } from "../types";
import { translate, useLocaleStore } from "../i18n";

const ALLOWED_URL_SCHEMES = new Set(["http:", "https:"]);

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
}

export const vaultCommands = {
  status: () => invoke<VaultStatus>("vault_status"),
  create: (password: string) => invoke<void>("create_vault", { password }),
  unlock: (password: string) => invoke<void>("unlock_vault", { password }),
  lock: () => invoke<void>("lock_vault"),
  changeMasterPassword: (currentPassword: string, newPassword: string) =>
    invoke<void>("change_master_password", { currentPassword, newPassword }),
  // Etapa 1 da exclusão do cofre: confere a senha mestra atual sem alterar nada — reaproveita a
  // mesma verificação real usada por change_master_password/Recovery Key/perguntas de segurança.
  verifyMasterPassword: (password: string) => invoke<void>("verify_master_password", { password }),
  // Etapa 2 já foi confirmada pela UI (usuário digitou "EXCLUIR") antes de chamar isto. O Rust
  // reautentica a senha mestra de novo aqui mesmo, então uma chamada direta sem a UI não
  // consegue pular a verificação.
  deleteVault: (password: string) => invoke<void>("delete_vault", { password }),
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
  import: (inPath: string, backupPassword: string, currentMasterPassword?: string) =>
    invoke<void>("import_backup", { inPath, backupPassword, currentMasterPassword: currentMasterPassword || null }),
};

// Defesa em profundidade (Fase 2): a capability `opener:allow-open-url` do Tauri já restringe
// o plugin a esquemas http(s) via ACL nativo, mas validamos aqui também para: (1) dar um erro
// claro em vez de uma rejeição silenciosa do plugin, e (2) não depender só da configuração do
// backend caso ela mude no futuro. Bloqueia especificamente `javascript:`, `data:`, `file:` e
// qualquer outro esquema que não seja http/https.
export function isAllowedExternalUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ALLOWED_URL_SCHEMES.has(parsed.protocol);
  } catch {
    return false;
  }
}

export async function openLoginUrl(url: string) {
  if (!url) return;
  if (!isAllowedExternalUrl(url)) {
    throw new Error(translate(useLocaleStore.getState().locale, "errors.invalidUrlScheme"));
  }
  await openUrlPlugin(url);
}

// Perguntas de segurança estão DESCONTINUADAS (podem ser quebradas offline por quem obtiver o
// arquivo do cofre): criar/editar foi desativado no Rust. Cofres antigos ainda podem listar,
// remover (com a senha mestra atual) e usar as perguntas existentes para recuperar o acesso.
export const securityQuestionCommands = {
  summary: () => invoke<SecurityQuestionsSummary>("security_questions_summary"),
  remove: (currentPassword: string, id: number) => invoke<void>("delete_security_question", { currentPassword, id }),
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
  generate: (currentPassword: string) => invoke<string>("generate_recovery_key", { currentPassword }),
  disable: (currentPassword: string) => invoke<void>("disable_recovery_key", { currentPassword }),
  unlockWithKey: (recoveryKey: string) => invoke<void>("unlock_with_recovery_key", { recoveryKey }),
};

// Gerador de senhas (Configurações → Gerador de Senhas): a geração roda inteiramente no backend
// com o CSPRNG do SO (ver src-tauri/src/commands/password_generator.rs) — o frontend nunca usa
// Math.random() nem gera nada localmente, e a senha resultante não é salva em nenhum lugar aqui.
export const passwordGeneratorCommands = {
  generate: (options: PasswordGeneratorOptions) => invoke<string>("generate_password", { options }),
};
