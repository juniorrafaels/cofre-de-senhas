use crate::commands::clipboard;
use crate::commands::history;
use crate::commands::platforms::Platform;
use crate::commands::projects::Project;
use crate::commands::tags::{self, Tag};
use crate::crypto;
use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tauri::{AppHandle, State};

const NAME_MAX: usize = 200;
const SHORT_FIELD_MAX: usize = 320;
const URL_MAX: usize = 2048;
// Campos de segredo agora chegam em texto puro (Fase 4 — a WebView nunca mais cifra/decifra
// diretamente); o teto é generoso mas limita o tamanho do que uma WebView comprometida poderia
// tentar gravar de uma vez.
const SECRET_PLAINTEXT_MAX: usize = 50_000;

const ACCOUNT_STATUSES: &[&str] = &["active", "blocked", "recovering", "suspended", "disabled", "archived"];
const TWO_FACTOR_METHODS: &[&str] = &["sms", "whatsapp", "email", "authenticator", "security_key", "other"];
const LIST_SCOPES: &[&str] = &["active", "trash", "all"];
const PRESERVABLE_FIELDS: &[&str] = &["notes", "two_factor_phone", "two_factor_email", "two_factor_app", "two_factor_notes"];

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

fn require_dek(state: &State<VaultState>) -> Result<[u8; 32], String> {
    state.with_dek(|dek| *dek).ok_or_else(|| "O cofre está bloqueado.".to_string())
}

fn validate_preserve_fields(fields: &[String]) -> Result<(), String> {
    for field in fields {
        if !PRESERVABLE_FIELDS.contains(&field.as_str()) {
            return Err("Campo inválido para preservação.".to_string());
        }
    }
    Ok(())
}

/// Cifra um valor opcional só se `enabled` e o valor (aparado) não estiver vazio — mesma regra
/// que antes vivia no frontend (`encryptOrPreserve`), agora resolvida no Rust com a DEK real.
fn encrypt_optional(dek: &[u8; 32], value: Option<&str>, enabled: bool) -> Result<Option<String>, String> {
    if !enabled {
        return Ok(None);
    }
    match value.map(str::trim) {
        Some(v) if !v.is_empty() => Ok(Some(crypto::encrypt_to_base64(dek, v)?)),
        _ => Ok(None),
    }
}

fn decrypt_optional(dek: &[u8; 32], ciphertext: Option<String>) -> Result<String, String> {
    match ciphertext {
        Some(c) => crypto::decrypt_from_base64(dek, &c),
        None => Ok(String::new()),
    }
}

#[derive(Serialize, Clone)]
pub struct Account {
    pub id: i64,
    pub name: String,
    pub platform_id: Option<i64>,
    pub category: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    // Fase 4: nunca mais o ciphertext da senha (nem de notes/2FA) — só a presença. O plaintext só
    // chega à WebView via `reveal_account_password`/`copy_account_password`, sob pedido explícito
    // e por ID, nunca junto com a listagem (ver SECURITY_AUDIT_PHASE_4.md).
    pub has_password: bool,
    pub login_url: Option<String>,
    pub website_url: Option<String>,
    pub favorite: i64,
    pub avatar_image_id: Option<i64>,
    pub status: String,
    pub deleted_at: Option<String>,
    pub two_factor_enabled: i64,
    pub two_factor_method: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct AccountWithRelations {
    #[serde(flatten)]
    pub account: Account,
    pub platform: Option<Platform>,
    pub tags: Vec<Tag>,
    pub projects: Vec<Project>,
}

#[derive(Deserialize)]
pub struct SaveAccountInput {
    pub name: String,
    pub platform_id: Option<i64>,
    pub category: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    /// Texto puro. `None`/vazio ao editar mantém a senha atual (nunca sobrescreve com nada);
    /// ao criar, significa "sem senha". A WebView nunca mais fornece/recebe ciphertext aqui.
    pub password: Option<String>,
    pub login_url: Option<String>,
    pub website_url: Option<String>,
    /// Texto puro — sempre cifrado internamente antes de gravar.
    pub notes: String,
    pub favorite: bool,
    pub avatar_image_id: Option<i64>,
    #[serde(rename = "tagNames")]
    pub tag_names: Vec<String>,
    #[serde(rename = "projectIds")]
    pub project_ids: Vec<i64>,
    pub status: String,
    pub two_factor_enabled: bool,
    pub two_factor_method: Option<String>,
    pub two_factor_phone: Option<String>,
    pub two_factor_email: Option<String>,
    pub two_factor_app: Option<String>,
    pub two_factor_notes: Option<String>,
    /// Nomes de campos (da allowlist `PRESERVABLE_FIELDS`) que falharam ao descriptografar no
    /// frontend e que o usuário não editou — nesses casos o Rust mantém o ciphertext antigo tal
    /// como está, sem tentar decifrar ou substituir por um valor vazio (nunca perder dado).
    #[serde(default)]
    pub preserve_fields: Vec<String>,
}

struct ValidatedAccountInput {
    name: String,
    category: Option<String>,
    username: Option<String>,
    email: Option<String>,
    login_url: Option<String>,
    website_url: Option<String>,
    status: String,
    two_factor_method: Option<String>,
}

fn validate_input(input: &SaveAccountInput) -> Result<ValidatedAccountInput, String> {
    let name = validate::trim_required(&input.name, "O nome da conta", NAME_MAX)?;
    let category = match &input.category {
        Some(v) => validate::trim_optional(v, 100, "A categoria")?,
        None => None,
    };
    let username = match &input.username {
        Some(v) => validate::trim_optional(v, SHORT_FIELD_MAX, "O nome de usuário")?,
        None => None,
    };
    let email = match &input.email {
        Some(v) => validate::trim_optional(v, SHORT_FIELD_MAX, "O e-mail")?,
        None => None,
    };
    let login_url = match &input.login_url {
        Some(v) => validate::trim_optional(v, URL_MAX, "A URL de login")?,
        None => None,
    };
    let website_url = match &input.website_url {
        Some(v) => validate::trim_optional(v, URL_MAX, "A URL do site")?,
        None => None,
    };
    validate::max_len_opt(&input.password, SECRET_PLAINTEXT_MAX, "A senha")?;
    validate::max_len(&input.notes, SECRET_PLAINTEXT_MAX, "As observações")?;
    validate::max_len_opt(&input.two_factor_phone, SECRET_PLAINTEXT_MAX, "O telefone de 2FA")?;
    validate::max_len_opt(&input.two_factor_email, SECRET_PLAINTEXT_MAX, "O e-mail de 2FA")?;
    validate::max_len_opt(&input.two_factor_app, SECRET_PLAINTEXT_MAX, "O app de 2FA")?;
    validate::max_len_opt(&input.two_factor_notes, SECRET_PLAINTEXT_MAX, "As observações de 2FA")?;
    validate_preserve_fields(&input.preserve_fields)?;

    let status = validate::one_of(&input.status, ACCOUNT_STATUSES, "O status da conta")?.to_string();
    let two_factor_method = validate::one_of_opt(input.two_factor_method.as_deref(), TWO_FACTOR_METHODS, "O método de 2FA")?
        .map(|s| s.to_string());

    Ok(ValidatedAccountInput { name, category, username, email, login_url, website_url, status, two_factor_method })
}

fn map_account(row: &rusqlite::Row) -> rusqlite::Result<Account> {
    let encrypted_password: Option<String> = row.get(6)?;
    Ok(Account {
        id: row.get(0)?,
        name: row.get(1)?,
        platform_id: row.get(2)?,
        category: row.get(3)?,
        username: row.get(4)?,
        email: row.get(5)?,
        has_password: encrypted_password.is_some(),
        login_url: row.get(7)?,
        website_url: row.get(8)?,
        favorite: row.get(9)?,
        avatar_image_id: row.get(10)?,
        status: row.get(11)?,
        deleted_at: row.get(12)?,
        two_factor_enabled: row.get(13)?,
        two_factor_method: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

const ACCOUNT_COLUMNS: &str = "a.id, a.name, a.platform_id, a.category, a.username, a.email, a.encrypted_password, \
     a.login_url, a.website_url, a.favorite, a.avatar_image_id, a.status, a.deleted_at, \
     a.two_factor_enabled, a.two_factor_method, a.created_at, a.updated_at";

#[tauri::command]
pub fn list_accounts_with_relations(app: AppHandle, state: State<VaultState>, scope: String) -> Result<Vec<AccountWithRelations>, String> {
    require_unlocked(&state)?;
    let scope = validate::one_of(&scope, LIST_SCOPES, "O escopo de listagem")?;
    let where_clause = match scope {
        "trash" => "WHERE a.deleted_at IS NOT NULL",
        "active" => "WHERE a.deleted_at IS NULL",
        _ => "",
    };

    let conn = db::open(&app)?;

    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS}, \
                p.name, p.icon, p.login_url, p.website_url, p.is_custom, p.logo_image_id, p.created_at, p.sort_order, p.system_key \
         FROM accounts a \
         LEFT JOIN platforms p ON p.id = a.platform_id \
         {where_clause} \
         ORDER BY a.name ASC"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows: Vec<(Account, Option<Platform>)> = stmt
        .query_map([], |row| {
            let account = map_account(row)?;
            let platform = if let Some(platform_id) = account.platform_id {
                Some(Platform {
                    id: platform_id,
                    name: row.get::<_, Option<String>>(17)?.unwrap_or_default(),
                    icon: row.get(18)?,
                    login_url: row.get(19)?,
                    website_url: row.get(20)?,
                    is_custom: row.get::<_, Option<i64>>(21)?.unwrap_or(0),
                    logo_image_id: row.get(22)?,
                    created_at: row.get::<_, Option<String>>(23)?.unwrap_or_default(),
                    sort_order: row.get::<_, Option<i64>>(24)?.unwrap_or(0),
                    system_key: row.get(25)?,
                })
            } else {
                None
            };
            Ok((account, platform))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut tags_by_account: HashMap<i64, Vec<Tag>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT at.account_id, t.id, t.name FROM account_tags at JOIN tags t ON t.id = at.tag_id")
            .map_err(|e| e.to_string())?;
        let tag_rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, Tag { id: row.get(1)?, name: row.get(2)? })))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        for (account_id, tag) in tag_rows {
            tags_by_account.entry(account_id).or_default().push(tag);
        }
    }

    let mut projects_by_account: HashMap<i64, Vec<Project>> = HashMap::new();
    {
        let sql = format!(
            "SELECT ap.account_id, pr.{} FROM account_projects ap JOIN projects pr ON pr.id = ap.project_id",
            "id, name, description, color, avatar_image_id, favorite, notes, created_at, updated_at, sort_order"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let project_rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    Project {
                        id: row.get(1)?,
                        name: row.get(2)?,
                        description: row.get(3)?,
                        color: row.get(4)?,
                        avatar_image_id: row.get(5)?,
                        favorite: row.get(6)?,
                        notes: row.get(7)?,
                        created_at: row.get(8)?,
                        updated_at: row.get(9)?,
                        sort_order: row.get(10)?,
                    },
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        for (account_id, project) in project_rows {
            projects_by_account.entry(account_id).or_default().push(project);
        }
    }

    Ok(rows
        .into_iter()
        .map(|(account, platform)| {
            let id = account.id;
            AccountWithRelations {
                tags: tags_by_account.remove(&id).unwrap_or_default(),
                projects: projects_by_account.remove(&id).unwrap_or_default(),
                platform,
                account,
            }
        })
        .collect())
}

#[tauri::command]
pub fn create_account(app: AppHandle, state: State<VaultState>, input: SaveAccountInput) -> Result<i64, String> {
    let validated = validate_input(&input)?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let now = db::now_iso();

    let encrypted_password = match input.password.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => Some(crypto::encrypt_to_base64(&dek, p)?),
        _ => None,
    };
    let notes_trimmed = input.notes.trim();
    let notes = if notes_trimmed.is_empty() { None } else { Some(crypto::encrypt_to_base64(&dek, notes_trimmed)?) };
    let two_factor_phone = encrypt_optional(&dek, input.two_factor_phone.as_deref(), input.two_factor_enabled)?;
    let two_factor_email = encrypt_optional(&dek, input.two_factor_email.as_deref(), input.two_factor_enabled)?;
    let two_factor_app = encrypt_optional(&dek, input.two_factor_app.as_deref(), input.two_factor_enabled)?;
    let two_factor_notes = encrypt_optional(&dek, input.two_factor_notes.as_deref(), input.two_factor_enabled)?;

    conn.execute(
        "INSERT INTO accounts \
          (name, platform_id, category, username, email, encrypted_password, login_url, website_url, notes, favorite, \
           avatar_image_id, status, two_factor_enabled, two_factor_method, two_factor_phone, two_factor_email, \
           two_factor_app, two_factor_notes, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            validated.name,
            input.platform_id,
            validated.category,
            validated.username,
            validated.email,
            encrypted_password,
            validated.login_url,
            validated.website_url,
            notes,
            input.favorite as i64,
            input.avatar_image_id,
            validated.status,
            input.two_factor_enabled as i64,
            validated.two_factor_method,
            two_factor_phone,
            two_factor_email,
            two_factor_app,
            two_factor_notes,
            now,
            now,
        ],
    )
    .map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    tags::sync_tags(&conn, "account_tags", "account_id", id, &input.tag_names)?;
    sync_account_projects(&conn, id, &input.project_ids)?;
    history::insert_history_row(&conn, id, "created", None)?;
    Ok(id)
}

#[tauri::command]
pub fn update_account(app: AppHandle, state: State<VaultState>, id: i64, input: SaveAccountInput) -> Result<(), String> {
    validate::positive_id(id, "id")?;
    let validated = validate_input(&input)?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;

    // Colunas cifradas atuais — usadas para (a) manter a senha se o usuário não digitou uma
    // nova, e (b) copiar de volta, sem decifrar, qualquer campo listado em `preserve_fields`.
    let (old_password, old_notes, old_phone, old_email, old_app, old_tf_notes): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT encrypted_password, notes, two_factor_phone, two_factor_email, two_factor_app, two_factor_notes \
             FROM accounts WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(|_| "Conta não encontrada.".to_string())?;

    let preserve: HashSet<&str> = input.preserve_fields.iter().map(|s| s.as_str()).collect();

    let encrypted_password = match input.password.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => Some(crypto::encrypt_to_base64(&dek, p)?),
        _ => old_password,
    };
    let notes = if preserve.contains("notes") {
        old_notes
    } else {
        let trimmed = input.notes.trim();
        if trimmed.is_empty() { None } else { Some(crypto::encrypt_to_base64(&dek, trimmed)?) }
    };
    let two_factor_phone = if preserve.contains("two_factor_phone") {
        old_phone
    } else {
        encrypt_optional(&dek, input.two_factor_phone.as_deref(), input.two_factor_enabled)?
    };
    let two_factor_email = if preserve.contains("two_factor_email") {
        old_email
    } else {
        encrypt_optional(&dek, input.two_factor_email.as_deref(), input.two_factor_enabled)?
    };
    let two_factor_app = if preserve.contains("two_factor_app") {
        old_app
    } else {
        encrypt_optional(&dek, input.two_factor_app.as_deref(), input.two_factor_enabled)?
    };
    let two_factor_notes = if preserve.contains("two_factor_notes") {
        old_tf_notes
    } else {
        encrypt_optional(&dek, input.two_factor_notes.as_deref(), input.two_factor_enabled)?
    };

    conn.execute(
        "UPDATE accounts SET \
          name = ?1, platform_id = ?2, category = ?3, username = ?4, email = ?5, \
          encrypted_password = ?6, login_url = ?7, website_url = ?8, notes = ?9, \
          favorite = ?10, avatar_image_id = ?11, status = ?12, two_factor_enabled = ?13, \
          two_factor_method = ?14, two_factor_phone = ?15, two_factor_email = ?16, \
          two_factor_app = ?17, two_factor_notes = ?18, updated_at = ?19 \
         WHERE id = ?20",
        params![
            validated.name,
            input.platform_id,
            validated.category,
            validated.username,
            validated.email,
            encrypted_password,
            validated.login_url,
            validated.website_url,
            notes,
            input.favorite as i64,
            input.avatar_image_id,
            validated.status,
            input.two_factor_enabled as i64,
            validated.two_factor_method,
            two_factor_phone,
            two_factor_email,
            two_factor_app,
            two_factor_notes,
            db::now_iso(),
            id,
        ],
    )
    .map_err(|e| e.to_string())?;
    tags::sync_tags(&conn, "account_tags", "account_id", id, &input.tag_names)?;
    sync_account_projects(&conn, id, &input.project_ids)?;
    Ok(())
}

fn sync_account_projects(conn: &Connection, account_id: i64, project_ids: &[i64]) -> Result<(), String> {
    conn.execute("DELETE FROM account_projects WHERE account_id = ?1", [account_id]).map_err(|e| e.to_string())?;
    for project_id in project_ids {
        validate::positive_id(*project_id, "project_id")?;
        conn.execute(
            "INSERT OR IGNORE INTO account_projects (account_id, project_id) VALUES (?1, ?2)",
            params![account_id, project_id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn delete_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("UPDATE accounts SET deleted_at = ?1 WHERE id = ?2", params![db::now_iso(), id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn restore_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("UPDATE accounts SET deleted_at = NULL WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn permanently_delete_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("DELETE FROM accounts WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn archive_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET status = 'archived', updated_at = ?1 WHERE id = ?2",
        params![db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    history::insert_history_row(&conn, id, "archived", None)?;
    Ok(())
}

#[tauri::command]
pub fn unarchive_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET status = 'active', updated_at = ?1 WHERE id = ?2",
        params![db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    history::insert_history_row(&conn, id, "restored", None)?;
    Ok(())
}

#[tauri::command]
pub fn toggle_favorite(app: AppHandle, state: State<VaultState>, id: i64, favorite: bool) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET favorite = ?1, updated_at = ?2 WHERE id = ?3",
        params![favorite as i64, db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn fetch_encrypted_password(conn: &Connection, id: i64) -> Result<Option<String>, String> {
    conn.query_row("SELECT encrypted_password FROM accounts WHERE id = ?1", [id], |row| row.get(0))
        .map_err(|_| "Conta não encontrada.".to_string())
}

/// Revela a senha de UMA conta específica, buscada pelo próprio Rust a partir do `id` — a
/// WebView nunca fornece ciphertext aqui (substitui o antigo `decrypt_secret` genérico). Sujeito
/// ao rate limiter: chamadas em massa (dump automatizado) são throttled, não instantâneas.
#[tauri::command]
pub fn reveal_account_password(app: AppHandle, state: State<VaultState>, id: i64) -> Result<String, String> {
    validate::positive_id(id, "id")?;
    state.reveal_limiter.check_and_record()?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let ciphertext = fetch_encrypted_password(&conn, id)?.ok_or_else(|| "Nenhuma senha cadastrada.".to_string())?;
    crypto::decrypt_from_base64(&dek, &ciphertext)
}

/// Decifra e copia para a área de transferência inteiramente no Rust — o plaintext nunca
/// atravessa para a WebView. Não passa pelo rate limiter (copiar não devolve segredo ao JS, e
/// copiar várias contas em sequência é um uso legítimo comum).
#[tauri::command]
pub fn copy_account_password(app: AppHandle, state: State<VaultState>, id: i64, clear_after_seconds: Option<u64>) -> Result<(), String> {
    validate::positive_id(id, "id")?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let ciphertext = fetch_encrypted_password(&conn, id)?.ok_or_else(|| "Nenhuma senha cadastrada.".to_string())?;
    let plaintext = zeroize::Zeroizing::new(crypto::decrypt_from_base64(&dek, &ciphertext)?);
    clipboard::write_secret_and_schedule_clear(&app, plaintext, clear_after_seconds)
}

/// Observações da conta, decifradas — usado para exibir/editar (nunca via `decrypt_secret`
/// genérico). Não passa pelo rate limiter: é buscado automaticamente ao abrir o detalhe/edição
/// de uma conta, não é uma ação de "revelar segredo" avulsa.
#[tauri::command]
pub fn get_account_notes(app: AppHandle, state: State<VaultState>, id: i64) -> Result<String, String> {
    validate::positive_id(id, "id")?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let ciphertext: Option<String> = conn
        .query_row("SELECT notes FROM accounts WHERE id = ?1", [id], |row| row.get(0))
        .map_err(|_| "Conta não encontrada.".to_string())?;
    decrypt_optional(&dek, ciphertext)
}

#[derive(Serialize, Default)]
pub struct TwoFactorDetails {
    pub phone: String,
    pub email: String,
    pub app: String,
    pub notes: String,
}

#[tauri::command]
pub fn get_account_two_factor_details(app: AppHandle, state: State<VaultState>, id: i64) -> Result<TwoFactorDetails, String> {
    validate::positive_id(id, "id")?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let (phone, email, app_field, notes): (Option<String>, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT two_factor_phone, two_factor_email, two_factor_app, two_factor_notes FROM accounts WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "Conta não encontrada.".to_string())?;

    Ok(TwoFactorDetails {
        phone: decrypt_optional(&dek, phone)?,
        email: decrypt_optional(&dek, email)?,
        app: decrypt_optional(&dek, app_field)?,
        notes: decrypt_optional(&dek, notes)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> SaveAccountInput {
        SaveAccountInput {
            name: "Conta de teste".to_string(),
            platform_id: None,
            category: None,
            username: None,
            email: None,
            password: None,
            login_url: None,
            website_url: None,
            notes: String::new(),
            favorite: false,
            avatar_image_id: None,
            tag_names: vec![],
            project_ids: vec![],
            status: "active".to_string(),
            two_factor_enabled: false,
            two_factor_method: None,
            two_factor_phone: None,
            two_factor_email: None,
            two_factor_app: None,
            two_factor_notes: None,
            preserve_fields: vec![],
        }
    }

    // Regressão de segurança (SECURITY_AUDIT_PHASE_3.md, seção "Validação no Rust"): `status` e
    // `two_factor_method` são colunas tratadas como enum fechado pela UI — a WebView não pode
    // gravar um valor livre nessas colunas, mesmo que consiga chamar o command diretamente.
    #[test]
    fn rejects_status_outside_allowlist() {
        let mut input = base_input();
        input.status = "totally_not_a_status".to_string();
        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn accepts_every_documented_status() {
        for status in ACCOUNT_STATUSES {
            let mut input = base_input();
            input.status = status.to_string();
            assert!(validate_input(&input).is_ok(), "status {status} deveria ser aceito");
        }
    }

    #[test]
    fn rejects_two_factor_method_outside_allowlist() {
        let mut input = base_input();
        input.two_factor_method = Some("carrier_pigeon".to_string());
        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let mut input = base_input();
        input.name = "   ".to_string();
        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn rejects_oversized_secret_fields() {
        let mut input = base_input();
        input.password = Some("x".repeat(SECRET_PLAINTEXT_MAX + 1));
        assert!(validate_input(&input).is_err());
    }

    #[test]
    fn rejects_scope_outside_allowlist() {
        assert!(validate::one_of("dump_everything", LIST_SCOPES, "escopo").is_err());
        assert!(validate::one_of("active", LIST_SCOPES, "escopo").is_ok());
    }

    // Fase 4 (SECURITY_AUDIT_PHASE_4.md): `preserve_fields` só aceita os nomes conhecidos —
    // impede que a WebView tente marcar uma coluna arbitrária como "não decifrar/sobrescrever".
    #[test]
    fn rejects_preserve_fields_outside_allowlist() {
        let mut input = base_input();
        input.preserve_fields = vec!["encrypted_password".to_string()];
        assert!(validate_input(&input).is_err());

        let mut input = base_input();
        input.preserve_fields = vec!["notes".to_string(), "two_factor_email".to_string()];
        assert!(validate_input(&input).is_ok());
    }

    #[test]
    fn encrypt_optional_respects_enabled_flag_and_blank_values() {
        let dek = [7u8; 32];
        assert_eq!(encrypt_optional(&dek, Some("+55 11 99999-9999"), false).unwrap(), None);
        assert_eq!(encrypt_optional(&dek, Some("   "), true).unwrap(), None);
        assert_eq!(encrypt_optional(&dek, None, true).unwrap(), None);

        let encrypted = encrypt_optional(&dek, Some("+55 11 99999-9999"), true).unwrap().unwrap();
        assert_ne!(encrypted, "+55 11 99999-9999");
        assert_eq!(crypto::decrypt_from_base64(&dek, &encrypted).unwrap(), "+55 11 99999-9999");
    }

    #[test]
    fn create_and_reveal_password_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let dek = [3u8; 32];

        let mut input = base_input();
        input.password = Some("XSS_TEST_PASSWORD_ROUNDTRIP".to_string());
        let validated = validate_input(&input).unwrap();
        let encrypted_password = crypto::encrypt_to_base64(&dek, "XSS_TEST_PASSWORD_ROUNDTRIP").unwrap();

        conn.execute(
            "INSERT INTO accounts (name, encrypted_password, status, two_factor_enabled, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 0, ?4, ?4)",
            params![validated.name, encrypted_password, validated.status, db::now_iso()],
        )
        .unwrap();
        let id = conn.last_insert_rowid();

        let ciphertext = fetch_encrypted_password(&conn, id).unwrap().unwrap();
        assert_ne!(ciphertext, "XSS_TEST_PASSWORD_ROUNDTRIP");
        assert_eq!(crypto::decrypt_from_base64(&dek, &ciphertext).unwrap(), "XSS_TEST_PASSWORD_ROUNDTRIP");
    }

    #[test]
    fn fetch_encrypted_password_rejects_missing_account() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        assert!(fetch_encrypted_password(&conn, 999).is_err());
    }
}
