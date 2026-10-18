export interface Platform {
  id: number;
  name: string;
  icon: string | null;
  login_url: string | null;
  website_url: string | null;
  is_custom: number;
  logo_image_id: number | null;
  created_at: string;
  sort_order: number;
  /** Identificador estável de uma plataforma oficial do Cofre (ver src-tauri/src/db.rs); null para plataformas criadas pelo usuário. */
  system_key: string | null;
}

export interface Tag {
  id: number;
  name: string;
}

export interface Project {
  id: number;
  name: string;
  description: string | null;
  color: string | null;
  avatar_image_id: number | null;
  favorite: number;
  notes: string | null;
  created_at: string;
  updated_at: string;
  sort_order: number;
}

export interface ProjectWithRelations extends Project {
  tags: Tag[];
  accountsCount: number;
  platformNames: string[];
}

export interface ProjectFormValues {
  id?: number;
  name: string;
  description: string;
  color: string | null;
  avatar_image_id: number | null;
  favorite: boolean;
  notes: string;
  tags: string[];
}

export interface SecurityQuestion {
  id: number;
  question: string;
  share_index: number;
  created_at: string;
}

export interface SecurityQuestionsSummary {
  count: number;
  max_allowed: number;
  min_required_for_recovery: number;
}

export interface RecoveryQuestion {
  id: number;
  question: string;
}

export interface RecoveryOutcome {
  success: boolean;
  message: string;
}

export interface ImageRecord {
  id: number;
  filename: string;
  original_name: string | null;
  name: string | null;
  hash: string;
  created_at: string;
}

export type AccountStatus = "active" | "blocked" | "recovering" | "suspended" | "disabled" | "archived";
export type TwoFactorMethod = "sms" | "whatsapp" | "email" | "authenticator" | "security_key" | "other";

// Ordem estável de exibição (ex.: <select>). Os labels traduzidos ficam em `src/i18n/enumLabels.ts`
// — os valores abaixo são identificadores internos e nunca mudam com o idioma.
export const ACCOUNT_STATUSES: AccountStatus[] = ["active", "blocked", "recovering", "suspended", "disabled", "archived"];
export const TWO_FACTOR_METHODS: TwoFactorMethod[] = ["sms", "whatsapp", "email", "authenticator", "security_key", "other"];

// Fase 4 (SECURITY_AUDIT_PHASE_4.md): a senha, as observações e os campos de 2FA nunca mais
// chegam cifrados a este tipo — só `has_password` sinaliza presença. O plaintext (quando
// necessário) vem de `accountSecretCommands.revealPassword/getNotes/getTwoFactorDetails`, sob
// pedido explícito e por ID, nunca junto com a listagem.
export interface Account {
  id: number;
  name: string;
  platform_id: number | null;
  category: string | null;
  username: string | null;
  email: string | null;
  has_password: boolean;
  login_url: string | null;
  website_url: string | null;
  favorite: number;
  avatar_image_id: number | null;
  status: AccountStatus;
  deleted_at: string | null;
  two_factor_enabled: number;
  two_factor_method: TwoFactorMethod | null;
  created_at: string;
  updated_at: string;
}

export interface AccountWithRelations extends Account {
  platform: Platform | null;
  tags: Tag[];
  projects: Project[];
}

export interface AccountFormValues {
  id?: number;
  name: string;
  platform_id: number | null;
  category: string;
  username: string;
  email: string;
  password: string;
  login_url: string;
  website_url: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  avatar_image_id: number | null;
  projectIds: number[];
  status: AccountStatus;
  two_factor_enabled: boolean;
  two_factor_method: TwoFactorMethod | null;
  two_factor_phone: string;
  two_factor_email: string;
  two_factor_app: string;
  two_factor_notes: string;
}

export type PropertyType = "text" | "number" | "phone" | "email" | "url" | "date" | "boolean" | "longtext";

// Ordem estável de exibição — labels traduzidos em `src/i18n/enumLabels.ts`.
export const PROPERTY_TYPES: PropertyType[] = ["text", "number", "phone", "email", "url", "date", "boolean", "longtext"];

export interface PropertyDefinition {
  id: number;
  name: string;
  type: PropertyType;
  created_at: string;
}

// `value` é sempre `null` para propriedades sensíveis na listagem (Fase 4) — `has_value` indica
// se existe algo cadastrado, sem expor o ciphertext. Para não sensíveis, `value` é o próprio
// texto puro (nunca foi segredo).
export interface AccountProperty {
  id: number;
  account_id: number;
  definition_id: number;
  value: string | null;
  has_value: boolean;
  is_sensitive: number;
  created_at: string;
  updated_at: string;
}

export interface AccountPropertyWithDefinition extends AccountProperty {
  name: string;
  type: PropertyType;
}

export interface AccountHistoryEntry {
  id: number;
  account_id: number;
  event: string;
  detail: string | null;
  created_at: string;
}

export type VaultStatusKind = "loading" | "uninitialized" | "locked" | "unlocked";

export type ThemePreference = "light" | "dark" | "system";
export type ViewMode = "grid" | "list";

// Idioma da interface (seção de i18n). `pt-BR` é sempre o padrão/fallback — ver useLocaleStore.
export type Locale = "pt-BR" | "en" | "es";
export const SUPPORTED_LOCALES: readonly Locale[] = ["pt-BR", "en", "es"];
export function isValidLocale(value: unknown): value is Locale {
  return typeof value === "string" && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}

export type ListColumnKey = "avatar" | "name" | "platform" | "username" | "email" | "project" | "status" | "tags" | "updated_at" | "two_factor";

// Ordem estável de exibição — labels traduzidos em `src/i18n/enumLabels.ts`.
export const ALL_LIST_COLUMNS: ListColumnKey[] = [
  "avatar",
  "name",
  "platform",
  "username",
  "email",
  "project",
  "status",
  "tags",
  "updated_at",
  "two_factor",
];

export const DEFAULT_LIST_COLUMNS: ListColumnKey[] = ["avatar", "name", "platform", "username", "status"];

// Níveis discretos do controle de escala das listagens/cards (seção 4 do pedido de ajuste) —
// zoom livre não é permitido, só esses passos, para nunca quebrar o layout.
export const LIST_SCALE_LEVELS = [75, 90, 100, 110, 125, 150, 175, 200] as const;
export type ListScale = (typeof LIST_SCALE_LEVELS)[number];

export interface AppSettings {
  theme: ThemePreference;
  language: Locale;
  autoLockMinutes: number;
  lockOnMinimize: boolean;
  clipboardClearEnabled: boolean;
  clipboardClearSeconds: number;
  viewMode: ViewMode;
  listColumns: ListColumnKey[];
  listScale: ListScale;
}

// ---------- Gerador de senhas (Configurações → Gerador de Senhas) ----------

export type PasswordCharClass = "numbers" | "upper" | "lower" | "special";
export type PasswordCountMode = "auto" | "fixed";

export interface PasswordClassOptions {
  enabled: boolean;
  mode: PasswordCountMode;
  count: number;
}

export interface PasswordGeneratorOptions {
  length: number;
  numbers: PasswordClassOptions;
  upper: PasswordClassOptions;
  lower: PasswordClassOptions;
  special: PasswordClassOptions;
  startType: PasswordCharClass | null;
  endType: PasswordCharClass | null;
  avoidSequences: boolean;
}

export type SortField = "name" | "created_at" | "updated_at";
export type SortDirection = "asc" | "desc";

export type ViewState =
  | { type: "dashboard" }
  | { type: "platform"; platformId: number }
  | { type: "favorites" }
  | { type: "settings" }
  | { type: "projects" }
  | { type: "project"; projectId: number }
  | { type: "archived" }
  | { type: "trash" };
