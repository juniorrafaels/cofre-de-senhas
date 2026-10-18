// Camada de acesso a dados do frontend.
//
// Fase 3 do hardening (ver SECURITY_AUDIT_PHASE_3.md): até a Fase 2, este arquivo falava SQL
// diretamente com o `vault.db` via `tauri-plugin-sql` (acesso irrestrito: SELECT/INSERT/UPDATE/
// DELETE livres a partir da WebView). Agora cada função aqui só invoca um Tauri command
// específico — a WebView não consegue mais montar uma query arbitrária, e toda validação de
// entrada, verificação de estado do cofre (bloqueado/desbloqueado) e parametrização de SQL
// acontece inteiramente no processo Rust (`src-tauri/src/commands/*.rs`).
//
// As assinaturas exportadas abaixo são propositalmente idênticas às da versão anterior (mesmo
// nome, mesmos parâmetros, mesmo tipo de retorno) para que nenhum componente precisasse mudar —
// só a implementação interna trocou de "SQL cru" para "invoke de command".
import { invoke } from "@tauri-apps/api/core";
import type {
  AccountHistoryEntry,
  AccountPropertyWithDefinition,
  AccountStatus,
  AccountWithRelations,
  ImageRecord,
  Platform,
  ProjectFormValues,
  ProjectWithRelations,
  PropertyDefinition,
  PropertyType,
  SecurityQuestion,
  Tag,
  TwoFactorMethod,
} from "../types";

// ---------- Platforms ----------

export async function listPlatforms(): Promise<Platform[]> {
  return invoke<Platform[]>("list_platforms");
}

export interface PlatformFormInput {
  name: string;
  icon: string | null;
  login_url: string | null;
  website_url: string | null;
  logo_image_id?: number | null;
}

export async function createPlatform(values: PlatformFormInput): Promise<number> {
  return invoke<number>("create_platform", { input: values });
}

export async function updatePlatform(id: number, values: PlatformFormInput): Promise<void> {
  await invoke<void>("update_platform", { id, input: values });
}

export async function deletePlatform(id: number): Promise<void> {
  await invoke<void>("delete_platform", { id });
}

export async function reassignAccountsPlatform(fromPlatformId: number, toPlatformId: number | null): Promise<void> {
  await invoke<void>("reassign_accounts_platform", { fromPlatformId, toPlatformId });
}

export async function reorderPlatforms(orderedIds: number[]): Promise<void> {
  await invoke<void>("reorder_platforms", { orderedIds });
}

// ---------- Tags ----------

export async function listTags(): Promise<Tag[]> {
  return invoke<Tag[]>("list_tags");
}

export interface TagWithUsage extends Tag {
  accountsCount: number;
  projectsCount: number;
}

export async function listTagsWithUsage(): Promise<TagWithUsage[]> {
  return invoke<TagWithUsage[]>("list_tags_with_usage");
}

export async function createTag(name: string): Promise<number> {
  return invoke<number>("create_tag", { name });
}

export async function renameTag(id: number, name: string): Promise<void> {
  await invoke<void>("rename_tag", { id, name });
}

export async function deleteTag(id: number): Promise<void> {
  await invoke<void>("delete_tag", { id });
}

// ---------- Accounts ----------

export type AccountListScope = "active" | "trash" | "all";

export async function listAccountsWithRelations(scope: AccountListScope = "active"): Promise<AccountWithRelations[]> {
  return invoke<AccountWithRelations[]>("list_accounts_with_relations", { scope });
}

// Fase 4 (SECURITY_AUDIT_PHASE_4.md): `password`/`notes`/`two_factor_*` chegam aqui em texto
// puro — é o Rust quem cifra internamente antes de gravar (nunca mais `secretCommands.encrypt`
// no frontend). `preserveFields` mantém o comportamento já existente de não sobrescrever um
// campo que falhou ao descriptografar e que o usuário não editou.
export interface SaveAccountInput {
  name: string;
  platform_id: number | null;
  category: string | null;
  username: string | null;
  email: string | null;
  password: string | null;
  login_url: string | null;
  website_url: string | null;
  notes: string;
  favorite: boolean;
  avatar_image_id: number | null;
  tagNames: string[];
  projectIds: number[];
  status: AccountStatus;
  two_factor_enabled: boolean;
  two_factor_method: TwoFactorMethod | null;
  two_factor_phone: string | null;
  two_factor_email: string | null;
  two_factor_app: string | null;
  two_factor_notes: string | null;
  preserveFields: string[];
}

export async function createAccount(input: SaveAccountInput): Promise<number> {
  const { preserveFields, ...rest } = input;
  return invoke<number>("create_account", { input: { ...rest, preserve_fields: preserveFields } });
}

export async function updateAccount(id: number, input: SaveAccountInput): Promise<void> {
  const { preserveFields, ...rest } = input;
  await invoke<void>("update_account", { id, input: { ...rest, preserve_fields: preserveFields } });
}

export async function deleteAccount(id: number): Promise<void> {
  await invoke<void>("delete_account", { id });
}

export async function restoreAccount(id: number): Promise<void> {
  await invoke<void>("restore_account", { id });
}

export async function permanentlyDeleteAccount(id: number): Promise<void> {
  await invoke<void>("permanently_delete_account", { id });
}

export async function archiveAccount(id: number): Promise<void> {
  await invoke<void>("archive_account", { id });
}

export async function unarchiveAccount(id: number): Promise<void> {
  await invoke<void>("unarchive_account", { id });
}

export async function toggleFavorite(id: number, favorite: boolean): Promise<void> {
  await invoke<void>("toggle_favorite", { id, favorite });
}

// ---------- Settings ----------

export async function getAllSettings(): Promise<Record<string, string>> {
  return invoke<Record<string, string>>("get_all_settings");
}

export async function setSetting(key: string, value: string): Promise<void> {
  await invoke<void>("set_setting", { key, value });
}

// ---------- Images ----------

export async function listImages(query?: string): Promise<ImageRecord[]> {
  return invoke<ImageRecord[]>("list_images", { query: query ?? null });
}

export async function updateImageName(id: number, name: string): Promise<void> {
  await invoke<void>("update_image_name", { id, name });
}

export async function countProjectsUsingImage(imageId: number): Promise<number> {
  return invoke<number>("count_projects_using_image", { imageId });
}

export async function countPlatformsUsingImage(imageId: number): Promise<number> {
  return invoke<number>("count_platforms_using_image", { imageId });
}

export async function getImageById(id: number): Promise<ImageRecord | null> {
  return invoke<ImageRecord | null>("get_image_by_id", { id });
}

export async function findImageByHash(hash: string): Promise<ImageRecord | null> {
  return invoke<ImageRecord | null>("find_image_by_hash", { hash });
}

export async function createImageRecord(filename: string, originalName: string, hash: string): Promise<ImageRecord> {
  return invoke<ImageRecord>("create_image_record", { filename, originalName, hash });
}

export async function deleteImageRecord(id: number): Promise<void> {
  await invoke<void>("delete_image_record", { id });
}

export async function countAccountsUsingImage(imageId: number): Promise<number> {
  return invoke<number>("count_accounts_using_image", { imageId });
}

export async function clearAvatarForImage(imageId: number): Promise<void> {
  await invoke<void>("clear_avatar_for_image", { imageId });
}

// ---------- Projects ----------

export async function listProjectsWithRelations(): Promise<ProjectWithRelations[]> {
  return invoke<ProjectWithRelations[]>("list_projects_with_relations");
}

export async function createProject(input: ProjectFormValues): Promise<number> {
  return invoke<number>("create_project", { input });
}

export async function updateProject(id: number, input: ProjectFormValues): Promise<void> {
  await invoke<void>("update_project", { id, input });
}

export async function deleteProject(id: number): Promise<void> {
  await invoke<void>("delete_project", { id });
}

export async function toggleProjectFavorite(id: number, favorite: boolean): Promise<void> {
  await invoke<void>("toggle_project_favorite", { id, favorite });
}

export async function reorderProjects(orderedIds: number[]): Promise<void> {
  await invoke<void>("reorder_projects", { orderedIds });
}

// ---------- Custom properties ----------

export async function listPropertyDefinitions(): Promise<PropertyDefinition[]> {
  return invoke<PropertyDefinition[]>("list_property_definitions");
}

export async function ensurePropertyDefinition(name: string, type: PropertyType): Promise<number> {
  return invoke<number>("ensure_property_definition", { name, propertyType: type });
}

export async function listAccountProperties(accountId: number): Promise<AccountPropertyWithDefinition[]> {
  return invoke<AccountPropertyWithDefinition[]>("list_account_properties", { accountId });
}

export async function createAccountProperty(
  accountId: number,
  definitionId: number,
  value: string,
  isSensitive: boolean,
): Promise<number> {
  return invoke<number>("create_account_property", { accountId, definitionId, value, isSensitive });
}

// Fase 4: `accountId` agora é obrigatório — o Rust confirma que a propriedade pertence a essa
// conta antes de alterar/excluir (ver SECURITY_AUDIT_PHASE_4.md, seção sobre `properties.rs`).
export async function updateAccountProperty(accountId: number, id: number, value: string, isSensitive: boolean): Promise<void> {
  await invoke<void>("update_account_property", { accountId, id, value, isSensitive });
}

export async function deleteAccountProperty(accountId: number, id: number): Promise<void> {
  await invoke<void>("delete_account_property", { accountId, id });
}

// ---------- Account history ----------

export async function logHistory(accountId: number, event: string, detail?: string | null): Promise<void> {
  await invoke<void>("log_account_history", { accountId, event, detail: detail ?? null });
}

export async function listAccountHistory(accountId: number): Promise<AccountHistoryEntry[]> {
  return invoke<AccountHistoryEntry[]>("list_account_history", { accountId });
}

// ---------- Security questions ----------

export async function listSecurityQuestions(): Promise<SecurityQuestion[]> {
  return invoke<SecurityQuestion[]>("list_security_questions");
}
