use crate::account_status::{self, UpdateBadge};
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
    /// Data do último login informada pelo usuário (`YYYY-MM-DD` ou instante UTC). Distinta de
    /// `created_at`/`updated_at` e da confirmação de atualização.
    pub last_login_at: Option<String>,
    /// Instante UTC da última confirmação manual de "conta atualizada". `None` quando ausente ou
    /// ilegível — nunca um valor inválido que a interface pudesse tratar como válido.
    pub update_confirmed_at: Option<String>,
    /// Fim da validade do selo (confirmação + 90 dias), se houver confirmação legível.
    pub update_expires_at: Option<String>,
    /// `"valid"`, `"expired"` ou `"none"` calculado no momento da listagem (a interface reavalia
    /// com o relógio atual ao renderizar).
    pub update_badge: String,
    /// Colunas de metadado (`name`, `username`...) que não puderam ser lidas (adulteradas, copiadas
    /// de outro campo/linha ou de versão desconhecida). Vazio no caso normal. O valor correspondente
    /// vem como `null` (ou como o texto-marcador, no caso do nome) — nunca um valor "quase certo".
    pub unreadable_fields: Vec<String>,
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
    /// Data do último login (opcional). Cifrada como metadado `enc:v2:`.
    #[serde(default)]
    pub last_login_at: Option<String>,
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
    last_login_at: Option<String>,
}

fn validate_input(input: &SaveAccountInput) -> Result<ValidatedAccountInput, String> {
    validate_input_keeping_legacy_urls(input, None, None)
}

/// `existing_login_url`/`existing_website_url` são os valores JÁ gravados no banco (lidos pelo
/// Rust, nunca enviados pela WebView). Uma URL idêntica à gravada é mantida sem revalidar, para
/// que contas antigas com URL inválida pelas regras novas continuem editáveis nos outros
/// campos; qualquer URL nova ou alterada passa pela validação completa.
fn validate_input_keeping_legacy_urls(
    input: &SaveAccountInput,
    existing_login_url: Option<&str>,
    existing_website_url: Option<&str>,
) -> Result<ValidatedAccountInput, String> {
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
        Some(v) => validate::http_url_optional_keeping_legacy(v, existing_login_url, URL_MAX, "A URL de login")?,
        None => None,
    };
    let website_url = match &input.website_url {
        Some(v) => validate::http_url_optional_keeping_legacy(v, existing_website_url, URL_MAX, "A URL do site")?,
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

    let last_login_at = match input.last_login_at.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Some(account_status::normalize_last_login(v, chrono::Utc::now())?),
        None => None,
    };

    Ok(ValidatedAccountInput { name, category, username, email, login_url, website_url, status, two_factor_method, last_login_at })
}

/// Texto mostrado no lugar de um nome que não autenticou (a coluna `name` não pode ser nula).
fn unreadable_name(id: i64) -> String {
    format!("[nome ilegível #{id}]")
}

/// Lê uma coluna de metadado opcional: `None` = vazio; legado em texto puro é aceito (cofre ainda
/// não migrado); `enc:v2:` é autenticado com (accounts, coluna, id). Falha = coluna registrada em
/// `unreadable` e valor `None`.
fn read_meta(dek: &[u8; 32], column: &'static str, id: i64, stored: Option<String>, unreadable: &mut Vec<String>) -> Option<String> {
    let stored = stored?;
    match crypto::decrypt_field(dek, "accounts", column, id, &stored) {
        Ok(value) => Some(value),
        Err(_) => {
            unreadable.push(column.to_string());
            None
        }
    }
}

fn write_meta(dek: &[u8; 32], column: &str, id: i64, value: Option<&str>) -> Result<Option<String>, String> {
    value.map(|v| crypto::encrypt_field(dek, "accounts", column, id, v)).transpose()
}

/// Valor a gravar numa coluna de metadado ao EDITAR. Se o valor guardado não é legível e a UI
/// devolveu vazio (ou o texto-marcador do nome), mantém o guardado como está em vez de apagá-lo.
fn resolve_meta(
    dek: &[u8; 32],
    column: &str,
    id: i64,
    stored: Option<&str>,
    incoming: Option<&str>,
    placeholder: Option<&str>,
) -> Result<Option<String>, String> {
    let stored_unreadable = stored.map(|s| crypto::decrypt_field(dek, "accounts", column, id, s).is_err()).unwrap_or(false);
    if stored_unreadable && (incoming.is_none() || incoming == placeholder) {
        return Ok(stored.map(str::to_string));
    }
    write_meta(dek, column, id, incoming)
}

fn map_account(row: &rusqlite::Row, dek: &[u8; 32]) -> rusqlite::Result<Account> {
    let id: i64 = row.get(0)?;
    let mut unreadable: Vec<String> = Vec::new();
    let name_stored: String = row.get(1)?;
    let name = match crypto::decrypt_field(dek, "accounts", "name", id, &name_stored) {
        Ok(v) => v,
        Err(_) => {
            unreadable.push("name".to_string());
            unreadable_name(id)
        }
    };
    let category = read_meta(dek, "category", id, row.get(3)?, &mut unreadable);
    let username = read_meta(dek, "username", id, row.get(4)?, &mut unreadable);
    let email = read_meta(dek, "email", id, row.get(5)?, &mut unreadable);
    let login_url = read_meta(dek, "login_url", id, row.get(7)?, &mut unreadable);
    let website_url = read_meta(dek, "website_url", id, row.get(8)?, &mut unreadable);
    let encrypted_password: Option<String> = row.get(6)?;
    let last_login_at = read_meta(dek, "last_login_at", id, row.get(17)?, &mut unreadable);
    let confirmed_raw: Option<String> = row.get(18)?;
    let (update_confirmed_at, update_expires_at, update_badge) =
        match account_status::update_badge(confirmed_raw.as_deref(), chrono::Utc::now()) {
            UpdateBadge::None => (None, None, "none"),
            UpdateBadge::Valid { confirmed_at, expires_at, .. } => {
                (Some(confirmed_at.to_rfc3339()), Some(expires_at.to_rfc3339()), "valid")
            }
            UpdateBadge::Expired { confirmed_at, expired_at } => {
                (Some(confirmed_at.to_rfc3339()), Some(expired_at.to_rfc3339()), "expired")
            }
        };
    Ok(Account {
        id,
        name,
        platform_id: row.get(2)?,
        category,
        username,
        email,
        has_password: encrypted_password.is_some(),
        login_url,
        website_url,
        favorite: row.get(9)?,
        avatar_image_id: row.get(10)?,
        status: row.get(11)?,
        deleted_at: row.get(12)?,
        two_factor_enabled: row.get(13)?,
        two_factor_method: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
        last_login_at,
        update_confirmed_at,
        update_expires_at,
        update_badge: update_badge.to_string(),
        unreadable_fields: unreadable,
    })
}

const ACCOUNT_COLUMNS: &str = "a.id, a.name, a.platform_id, a.category, a.username, a.email, a.encrypted_password, \
     a.login_url, a.website_url, a.favorite, a.avatar_image_id, a.status, a.deleted_at, \
     a.two_factor_enabled, a.two_factor_method, a.created_at, a.updated_at, a.last_login_at, a.update_confirmed_at";

#[tauri::command]
pub fn list_accounts_with_relations(app: AppHandle, state: State<VaultState>, scope: String) -> Result<Vec<AccountWithRelations>, String> {
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    list_accounts_core(&conn, &dek, &scope)
}

/// Os metadados (inclusive o nome) são lidos já descriptografados; por isso a ordenação por nome
/// acontece aqui, em Rust, e não mais no SQL. A comparação de `String` é por bytes UTF-8 — a mesma
/// semântica do `ORDER BY name` (collation BINARY) de antes; empates mantêm a ordem por id.
fn list_accounts_core(conn: &Connection, dek: &[u8; 32], scope: &str) -> Result<Vec<AccountWithRelations>, String> {
    let scope = validate::one_of(scope, LIST_SCOPES, "O escopo de listagem")?;
    let where_clause = match scope {
        "trash" => "WHERE a.deleted_at IS NOT NULL",
        "active" => "WHERE a.deleted_at IS NULL",
        _ => "",
    };

    let sql = format!(
        "SELECT {ACCOUNT_COLUMNS}, \
                p.name, p.icon, p.login_url, p.website_url, p.is_custom, p.logo_image_id, p.created_at, p.sort_order, p.system_key \
         FROM accounts a \
         LEFT JOIN platforms p ON p.id = a.platform_id \
         {where_clause} \
         ORDER BY a.id ASC"
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let mut rows: Vec<(Account, Option<Platform>)> = stmt
        .query_map([], |row| {
            let account = map_account(row, dek)?;
            let platform = if let Some(platform_id) = account.platform_id {
                Some(Platform {
                    id: platform_id,
                    name: row.get::<_, Option<String>>(19)?.unwrap_or_default(),
                    icon: row.get(20)?,
                    login_url: row.get(21)?,
                    website_url: row.get(22)?,
                    is_custom: row.get::<_, Option<i64>>(23)?.unwrap_or(0),
                    logo_image_id: row.get(24)?,
                    created_at: row.get::<_, Option<String>>(25)?.unwrap_or_default(),
                    sort_order: row.get::<_, Option<i64>>(26)?.unwrap_or(0),
                    system_key: row.get(27)?,
                })
            } else {
                None
            };
            Ok((account, platform))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    rows.sort_by(|a, b| a.0.name.cmp(&b.0.name));

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
    create_account_core(&conn, &dek, &input, validated)
}

/// Gravação de uma conta nova, separada do command para ser exercitada em testes (inclusive a
/// auditoria de "o que fica em texto claro no arquivo SQLite").
///
/// Os metadados (`name`, `category`, `username`, `email`, `login_url`, `website_url`) são
/// cifrados em `enc:v2:` com AAD que inclui o id da linha — que só existe depois do INSERT. Por
/// isso a linha nasce com marcadores vazios (nunca o texto puro) e é atualizada com os valores
/// cifrados, tudo na mesma transação: uma falha no meio desfaz a conta inteira.
fn create_account_core(conn: &Connection, dek: &[u8; 32], input: &SaveAccountInput, validated: ValidatedAccountInput) -> Result<i64, String> {
    let dek = *dek;
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

    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO accounts \
          (name, platform_id, encrypted_password, notes, favorite, \
           avatar_image_id, status, two_factor_enabled, two_factor_method, two_factor_phone, two_factor_email, \
           two_factor_app, two_factor_notes, created_at, updated_at) \
         VALUES ('', ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            input.platform_id,
            encrypted_password,
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
    let id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE accounts SET name = ?1, category = ?2, username = ?3, email = ?4, login_url = ?5, website_url = ?6, last_login_at = ?7 WHERE id = ?8",
        params![
            crypto::encrypt_field(&dek, "accounts", "name", id, &validated.name)?,
            write_meta(&dek, "category", id, validated.category.as_deref())?,
            write_meta(&dek, "username", id, validated.username.as_deref())?,
            write_meta(&dek, "email", id, validated.email.as_deref())?,
            write_meta(&dek, "login_url", id, validated.login_url.as_deref())?,
            write_meta(&dek, "website_url", id, validated.website_url.as_deref())?,
            write_meta(&dek, "last_login_at", id, validated.last_login_at.as_deref())?,
            id,
        ],
    )
    .map_err(|e| e.to_string())?;
    tags::sync_tags(&tx, "account_tags", "account_id", id, &input.tag_names)?;
    sync_account_projects(&tx, id, &input.project_ids)?;
    history::insert_history_row(&tx, &dek, id, "created", None)?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(id)
}

/// URLs atualmente gravadas na conta (login, site). Lidas pelo Rust a cada edição: é o que decide
/// se uma URL enviada é "inalterada" (preservada) ou "nova/alterada" (validada por completo).
fn fetch_existing_urls(conn: &Connection, id: i64) -> Result<(Option<String>, Option<String>), String> {
    conn.query_row("SELECT login_url, website_url FROM accounts WHERE id = ?1", [id], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })
    .map_err(|_| "Conta não encontrada.".to_string())
}

#[tauri::command]
pub fn update_account(app: AppHandle, state: State<VaultState>, id: i64, input: SaveAccountInput) -> Result<(), String> {
    validate::positive_id(id, "id")?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    // URLs já gravadas: uma URL inalterada é preservada mesmo que seja inválida pelas regras
    // novas (conta antiga); uma URL nova ou alterada é validada por completo.
    let (existing_login_url, existing_website_url) = fetch_existing_urls(&conn, id)?;
    let validated =
        validate_input_keeping_legacy_urls(&input, existing_login_url.as_deref(), existing_website_url.as_deref())?;
    update_account_core(&conn, &dek, id, &input, validated)
}

fn update_account_core(conn: &Connection, dek: &[u8; 32], id: i64, input: &SaveAccountInput, validated: ValidatedAccountInput) -> Result<(), String> {
    let dek = *dek;

    // Colunas atuais — usadas para (a) manter a senha se o usuário não digitou uma nova, (b) copiar
    // de volta, sem decifrar, qualquer campo listado em `preserve_fields` e (c) não apagar um
    // metadado ilegível (adulterado) só porque a UI o recebeu como vazio.
    #[allow(clippy::type_complexity)]
    let (old_password, old_notes, old_phone, old_email, old_app, old_tf_notes, old_meta): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        [Option<String>; 7],
    ) = conn
        .query_row(
            "SELECT encrypted_password, notes, two_factor_phone, two_factor_email, two_factor_app, two_factor_notes, \
                    name, category, username, email, login_url, website_url, last_login_at \
             FROM accounts WHERE id = ?1",
            [id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    [row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?],
                ))
            },
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

    let placeholder = unreadable_name(id);
    let [old_name, old_category, old_username, old_email_meta, old_login_url, old_website_url, old_last_login] = old_meta;
    let name = resolve_meta(&dek, "name", id, old_name.as_deref(), Some(&validated.name), Some(&placeholder))?
        .ok_or_else(|| "O nome da conta é obrigatório.".to_string())?;
    let category = resolve_meta(&dek, "category", id, old_category.as_deref(), validated.category.as_deref(), None)?;
    let username = resolve_meta(&dek, "username", id, old_username.as_deref(), validated.username.as_deref(), None)?;
    let email = resolve_meta(&dek, "email", id, old_email_meta.as_deref(), validated.email.as_deref(), None)?;
    let login_url = resolve_meta(&dek, "login_url", id, old_login_url.as_deref(), validated.login_url.as_deref(), None)?;
    let website_url = resolve_meta(&dek, "website_url", id, old_website_url.as_deref(), validated.website_url.as_deref(), None)?;
    let last_login_at = resolve_meta(&dek, "last_login_at", id, old_last_login.as_deref(), validated.last_login_at.as_deref(), None)?;

    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE accounts SET \
          name = ?1, platform_id = ?2, category = ?3, username = ?4, email = ?5, \
          encrypted_password = ?6, login_url = ?7, website_url = ?8, notes = ?9, \
          favorite = ?10, avatar_image_id = ?11, status = ?12, two_factor_enabled = ?13, \
          two_factor_method = ?14, two_factor_phone = ?15, two_factor_email = ?16, \
          two_factor_app = ?17, two_factor_notes = ?18, updated_at = ?19, last_login_at = ?20 \
         WHERE id = ?21",
        params![
            name,
            input.platform_id,
            category,
            username,
            email,
            encrypted_password,
            login_url,
            website_url,
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
            last_login_at,
            id,
        ],
    )
    .map_err(|e| e.to_string())?;
    tags::sync_tags(&tx, "account_tags", "account_id", id, &input.tag_names)?;
    sync_account_projects(&tx, id, &input.project_ids)?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

/// Confirma manualmente que a conta está atualizada (renova o selo por 90 dias). É a ÚNICA
/// operação que grava `update_confirmed_at`: editar, abrir ou visualizar a conta não passa por
/// aqui. Não altera `updated_at` nem `last_login_at` — confirmar a atualização não é um login.
#[tauri::command]
pub fn mark_account_updated(app: AppHandle, state: State<VaultState>, id: i64) -> Result<String, String> {
    let dek = require_dek(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    mark_account_updated_core(&conn, &dek, id, chrono::Utc::now())
}

fn mark_account_updated_core(conn: &Connection, dek: &[u8; 32], id: i64, now: chrono::DateTime<chrono::Utc>) -> Result<String, String> {
    let stamp = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute("UPDATE accounts SET update_confirmed_at = ?1 WHERE id = ?2 AND deleted_at IS NULL", params![stamp, id])
        .map_err(|e| e.to_string())?;
    if changed == 0 {
        return Err("Conta não encontrada.".to_string());
    }
    history::insert_history_row(&tx, dek, id, "update_confirmed", None)?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(stamp)
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
    let dek = require_dek(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET status = 'archived', updated_at = ?1 WHERE id = ?2",
        params![db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    history::insert_history_row(&conn, &dek, id, "archived", None)?;
    Ok(())
}

#[tauri::command]
pub fn unarchive_account(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    let dek = require_dek(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET status = 'active', updated_at = ?1 WHERE id = ?2",
        params![db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    history::insert_history_row(&conn, &dek, id, "restored", None)?;
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
            last_login_at: None,
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
    fn new_dangerous_or_schemeless_urls_are_rejected_on_create() {
        for bad in ["javascript:alert(1)", "file:///C:/x", "example.com", "https://good.com\\@evil.com"] {
            let mut input = base_input();
            input.login_url = Some(bad.to_string());
            assert!(validate_input(&input).is_err(), "login_url {bad:?} deveria ser rejeitada");
            let mut input = base_input();
            input.website_url = Some(bad.to_string());
            assert!(validate_input(&input).is_err(), "website_url {bad:?} deveria ser rejeitada");
        }
        let mut input = base_input();
        input.login_url = Some("HTTPS://example.com/login".to_string());
        assert_eq!(validate_input(&input).unwrap().login_url.as_deref(), Some("https://example.com/login"));
    }

    // Conta antiga (URL inválida pelas regras novas): editar OUTRO campo não pode ser bloqueado,
    // e a URL antiga não é reescrita. Já mudar a URL exige a validação completa.
    #[test]
    fn legacy_urls_are_kept_when_unchanged_but_changes_are_validated() {
        let mut input = base_input();
        input.name = "Conta antiga editada".to_string();
        input.login_url = Some("example.com".to_string());
        input.website_url = Some("javascript:alert(1)".to_string());
        // As URLs enviadas são idênticas às gravadas: preservadas, sem erro.
        let ok = validate_input_keeping_legacy_urls(&input, Some("example.com"), Some("javascript:alert(1)")).unwrap();
        assert_eq!(ok.login_url.as_deref(), Some("example.com"));
        assert_eq!(ok.website_url.as_deref(), Some("javascript:alert(1)"));
        assert_eq!(ok.name, "Conta antiga editada");

        // Sem valor gravado igual, a mesma entrada é rejeitada (a WebView não escolhe a exceção).
        assert!(validate_input_keeping_legacy_urls(&input, None, None).is_err());
        assert!(validate_input_keeping_legacy_urls(&input, Some("outro.com"), Some("javascript:alert(1)")).is_err());
        assert!(validate_input_keeping_legacy_urls(&input, Some("example.com"), Some("https://ok.com")).is_err());

        // URL alterada para uma válida: aceita; apagada: aceita.
        input.login_url = Some("https://example.com".to_string());
        input.website_url = None;
        assert!(validate_input_keeping_legacy_urls(&input, Some("example.com"), Some("javascript:alert(1)")).is_ok());
    }

    // Banco SQLite real (em memória): conta antiga com URLs que as regras novas rejeitariam. O que
    // decide "inalterada" é o valor lido do banco, não algo informado pela WebView.
    #[test]
    fn legacy_account_urls_survive_edit_of_other_fields_against_a_real_database() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        conn.execute(
            "INSERT INTO accounts (name, login_url, website_url, status, two_factor_enabled, created_at, updated_at) \
             VALUES ('Antiga', 'example.com', 'javascript:alert(1)', 'active', 0, ?1, ?1)",
            params![db::now_iso()],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        let (login, website) = fetch_existing_urls(&conn, id).unwrap();
        assert_eq!(login.as_deref(), Some("example.com"));
        assert_eq!(website.as_deref(), Some("javascript:alert(1)"));

        // Editar só o nome: as URLs enviadas são as gravadas, nada é bloqueado nem reescrito.
        let mut input = base_input();
        input.name = "Antiga renomeada".to_string();
        input.login_url = login.clone();
        input.website_url = website.clone();
        let ok = validate_input_keeping_legacy_urls(&input, login.as_deref(), website.as_deref()).unwrap();
        assert_eq!((ok.login_url, ok.website_url), (login.clone(), website.clone()));

        // Trocar a URL por outra inválida (ou perigosa) continua sendo rejeitado.
        input.login_url = Some("file:///C:/x".to_string());
        assert!(validate_input_keeping_legacy_urls(&input, login.as_deref(), website.as_deref()).is_err());

        // Conta inexistente continua dando o mesmo erro de antes.
        assert_eq!(fetch_existing_urls(&conn, id + 1000).unwrap_err(), "Conta não encontrada.");
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

    const TEST_DEK: [u8; 32] = [11u8; 32];

    fn input_named(name: &str) -> SaveAccountInput {
        let mut input = base_input();
        input.name = name.to_string();
        input
    }

    fn create(conn: &Connection, input: &SaveAccountInput) -> i64 {
        let validated = validate_input(input).unwrap();
        create_account_core(conn, &TEST_DEK, input, validated).unwrap()
    }

    fn list(conn: &Connection, scope: &str) -> Vec<AccountWithRelations> {
        list_accounts_core(conn, &TEST_DEK, scope).unwrap()
    }

    fn mem_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        conn
    }

    fn raw_col(conn: &Connection, column: &str, id: i64) -> Option<String> {
        conn.query_row(&format!("SELECT {column} FROM accounts WHERE id = ?1"), [id], |r| r.get(0)).unwrap()
    }

    const AUDIT_MARKERS: [&str; 12] = [
        "audit-name-7391",
        "audit-category-7391",
        "audit-user-7391",
        "audit-email-7391@example.invalid",
        "audit-login-7391",
        "audit-site-7391",
        "audit-history-detail-7391",
        "audit-password-7391",
        "audit-notes-7391",
        "audit-2fa-phone-7391",
        "audit-2fa-email-7391",
        "audit-2fa-app-7391",
    ];

    fn markers_in_dir(dir: &std::path::Path) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            for m in AUDIT_MARKERS {
                if bytes.windows(m.len()).any(|w| w == m.as_bytes()) {
                    found.push((entry.file_name().to_string_lossy().to_string(), m.to_string()));
                }
            }
        }
        found
    }

    /// AUDITORIA (campo a campo, versão pós-criptografia de metadados): grava uma conta pelo mesmo
    /// caminho de `create_account` com marcadores fictícios em todos os campos e procura os bytes
    /// no arquivo SQLite, no `-wal` e no `.vaultbackup`. Só a etiqueta (fora desta fase) segue em claro.
    #[test]
    fn audit_no_account_or_history_marker_appears_in_plaintext_on_disk_or_in_backups() {
        let dir = std::env::temp_dir().join(format!("cofre-audit-{}", crypto::random_bytes(6).iter().map(|b| format!("{b:02x}")).collect::<String>()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("vault.db");

        let mut input = base_input();
        input.name = "audit-name-7391".into();
        input.category = Some("audit-category-7391".into());
        input.username = Some("audit-user-7391".into());
        input.email = Some("audit-email-7391@example.invalid".into());
        input.password = Some("audit-password-7391".into());
        input.login_url = Some("https://audit-login-7391.example.invalid".into());
        input.website_url = Some("https://audit-site-7391.example.invalid".into());
        input.notes = "audit-notes-7391".into();
        input.tag_names = vec!["audit-tag-7391".into()];
        input.two_factor_enabled = true;
        input.two_factor_method = Some("sms".into());
        input.two_factor_phone = Some("audit-2fa-phone-7391".into());
        input.two_factor_email = Some("audit-2fa-email-7391@example.invalid".into());
        input.two_factor_app = Some("audit-2fa-app-7391".into());
        input.two_factor_notes = Some("audit-2fa-notes-7391".into());

        let conn = Connection::open(&db_path).unwrap();
        db::init_schema(&conn).unwrap();
        let id = create(&conn, &input);
        history::insert_history_row(&conn, &TEST_DEK, id, "username_changed", Some("audit-history-detail-7391 → audit-history-detail-7391")).unwrap();
        let mut update = input.clone_for_test();
        update.username = Some("audit-user-7391".into());
        update_account_core(&conn, &TEST_DEK, id, &update, validate_input(&update).unwrap()).unwrap();

        // 1) Conexão ainda aberta: o WAL existe e também não pode ter nada em claro.
        assert!(dir.join("vault.db-wal").exists(), "o teste deveria estar exercitando o WAL");
        let open_found: Vec<_> = markers_in_dir(&dir).into_iter().filter(|(_, m)| m != "audit-tag-7391").collect();
        assert_eq!(open_found, Vec::<(String, String)>::new(), "marcadores em claro com a conexão aberta");

        // 2) Backup `.vaultbackup`
        let backup = crate::commands::backup::backup_bytes_for_test(&conn, "senha-do-backup-audit");
        for m in AUDIT_MARKERS.iter().chain(["audit-tag-7391"].iter()) {
            assert!(!backup.windows(m.len()).any(|w| w == m.as_bytes()), "{m} não pode aparecer no .vaultbackup");
        }
        drop(conn);

        // 3) Conexão fechada ("cofre bloqueado"): só o arquivo.
        let closed_found: Vec<_> = markers_in_dir(&dir).into_iter().filter(|(_, m)| m != "audit-tag-7391").collect();
        assert_eq!(closed_found, Vec::<(String, String)>::new(), "marcadores em claro com o cofre fechado");

        // 4) Lendo de volta com a DEK, tudo continua disponível.
        let conn = Connection::open(&db_path).unwrap();
        let account = &list(&conn, "active")[0].account;
        assert_eq!(account.name, "audit-name-7391");
        assert_eq!(account.username.as_deref(), Some("audit-user-7391"));
        assert_eq!(account.email.as_deref(), Some("audit-email-7391@example.invalid"));
        assert_eq!(account.login_url.as_deref(), Some("https://audit-login-7391.example.invalid"));
        assert_eq!(account.category.as_deref(), Some("audit-category-7391"));
        assert!(account.unreadable_fields.is_empty());
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    impl SaveAccountInput {
        fn clone_for_test(&self) -> SaveAccountInput {
            SaveAccountInput {
                name: self.name.clone(),
                platform_id: self.platform_id,
                category: self.category.clone(),
                username: self.username.clone(),
                email: self.email.clone(),
                password: None,
                login_url: self.login_url.clone(),
                website_url: self.website_url.clone(),
                notes: self.notes.clone(),
                favorite: self.favorite,
                avatar_image_id: self.avatar_image_id,
                tag_names: self.tag_names.clone(),
                project_ids: self.project_ids.clone(),
                status: self.status.clone(),
                two_factor_enabled: self.two_factor_enabled,
                two_factor_method: self.two_factor_method.clone(),
                two_factor_phone: self.two_factor_phone.clone(),
                two_factor_email: self.two_factor_email.clone(),
                two_factor_app: self.two_factor_app.clone(),
                two_factor_notes: self.two_factor_notes.clone(),
                last_login_at: self.last_login_at.clone(),
                preserve_fields: self.preserve_fields.clone(),
            }
        }
    }

    #[test]
    fn create_stores_v2_ciphertext_and_list_reads_it_back() {
        let conn = mem_conn();
        let mut input = input_named("audit-name-7391");
        input.username = Some("audit-user-7391".into());
        input.email = Some("audit-email-7391@example.invalid".into());
        let id = create(&conn, &input);

        for column in ["name", "username", "email"] {
            assert!(raw_col(&conn, column, id).unwrap().starts_with("enc:v2:"), "{column} deveria estar cifrado");
        }
        assert_eq!(raw_col(&conn, "category", id), None, "campo vazio continua NULL (não vira ciphertext)");
        let listed = &list(&conn, "active")[0].account;
        assert_eq!((listed.name.as_str(), listed.username.as_deref()), ("audit-name-7391", Some("audit-user-7391")));
        assert_eq!(listed.category, None);
    }

    #[test]
    fn edit_and_delete_keep_working_with_encrypted_metadata() {
        let conn = mem_conn();
        let id = create(&conn, &input_named("conta-a"));
        let mut edited = input_named("conta-a-editada");
        edited.username = Some("novo-usuario-fictício".into());
        edited.email = Some("novo@example.invalid".into());
        update_account_core(&conn, &TEST_DEK, id, &edited, validate_input(&edited).unwrap()).unwrap();

        let listed = &list(&conn, "active")[0].account;
        assert_eq!(listed.name, "conta-a-editada");
        assert_eq!(listed.username.as_deref(), Some("novo-usuario-fictício"));
        assert!(raw_col(&conn, "username", id).unwrap().starts_with("enc:v2:"));

        // limpar um campo na edição também funciona (vira NULL)
        let mut cleared = input_named("conta-a-editada");
        cleared.username = None;
        update_account_core(&conn, &TEST_DEK, id, &cleared, validate_input(&cleared).unwrap()).unwrap();
        assert_eq!(raw_col(&conn, "username", id), None);

        // lixeira e exclusão definitiva (mesmo SQL de `delete_account`/`permanently_delete_account`)
        conn.execute("UPDATE accounts SET deleted_at = 'now' WHERE id = ?1", [id]).unwrap();
        assert!(list(&conn, "active").is_empty());
        assert_eq!(list(&conn, "trash").len(), 1);
        assert_eq!(list(&conn, "all")[0].account.name, "conta-a-editada");
        conn.execute("DELETE FROM accounts WHERE id = ?1", [id]).unwrap();
        assert!(list(&conn, "all").is_empty());
    }

    // A ordenação por nome saiu do SQL para o Rust: tem que reproduzir exatamente o `ORDER BY name`
    // (collation BINARY) de um banco com os mesmos nomes em texto puro — inclusive maiúsculas,
    // acentos e empates.
    #[test]
    fn name_ordering_matches_the_previous_sql_order_by() {
        let names = ["banco", "Banco", "alfa", "Zeta", "álamo", "alfa", "10-contas", "2-contas", "_x", "Ωmega", "a b", "ab"];
        let encrypted = mem_conn();
        let legacy = mem_conn();
        for name in names {
            create(&encrypted, &input_named(name));
            legacy.execute("INSERT INTO accounts (name, created_at, updated_at) VALUES (?1, 'now', 'now')", [name]).unwrap();
        }
        let sql_order: Vec<String> = legacy
            .prepare("SELECT name FROM accounts ORDER BY name ASC")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let rust_order: Vec<String> = list(&encrypted, "active").into_iter().map(|a| a.account.name).collect();
        assert_eq!(rust_order, sql_order);
    }

    #[test]
    fn legacy_plaintext_vault_is_readable_before_any_migration() {
        let conn = mem_conn();
        conn.execute(
            "INSERT INTO accounts (name, username, email, login_url, created_at, updated_at) \
             VALUES ('legado-fictício', 'usuario-legado', 'legado@example.invalid', 'https://legado.example.invalid', 'now', 'now')",
            [],
        )
        .unwrap();
        let listed = &list(&conn, "active")[0].account;
        assert_eq!(listed.name, "legado-fictício");
        assert_eq!(listed.email.as_deref(), Some("legado@example.invalid"));
        assert!(listed.unreadable_fields.is_empty());
        // editar converte esse registro para v2 sem perder nada
        let mut edited = input_named("legado-fictício");
        edited.username = Some("usuario-legado".into());
        update_account_core(&conn, &TEST_DEK, 1, &edited, validate_input(&edited).unwrap()).unwrap();
        assert!(raw_col(&conn, "username", 1).unwrap().starts_with("enc:v2:"));
        assert_eq!(list(&conn, "active")[0].account.username.as_deref(), Some("usuario-legado"));
    }

    // AAD: copiar um ciphertext VÁLIDO para outra conta ou outra coluna não retorna o valor da outra
    // conta — o campo vira "ilegível", é sinalizado, e nunca aparece o valor errado.
    #[test]
    fn ciphertext_copied_between_accounts_or_columns_is_reported_unreadable() {
        let conn = mem_conn();
        let mut a = input_named("conta-a");
        a.username = Some("usuario-da-conta-a".into());
        a.email = Some("a@example.invalid".into());
        let mut b = input_named("conta-b");
        b.username = Some("usuario-da-conta-b".into());
        let id_a = create(&conn, &a);
        let id_b = create(&conn, &b);

        let a_username = raw_col(&conn, "username", id_a).unwrap();
        conn.execute("UPDATE accounts SET username = ?1 WHERE id = ?2", rusqlite::params![a_username, id_b]).unwrap(); // outra conta
        conn.execute("UPDATE accounts SET category = ?1 WHERE id = ?2", rusqlite::params![a_username, id_a]).unwrap(); // outra coluna
        let a_name = raw_col(&conn, "name", id_a).unwrap();
        conn.execute("UPDATE accounts SET name = ?1 WHERE id = ?2", rusqlite::params![a_name, id_b]).unwrap(); // nome trocado

        let listed = list(&conn, "active");
        let acc_a = &listed.iter().find(|x| x.account.id == id_a).unwrap().account;
        let acc_b = &listed.iter().find(|x| x.account.id == id_b).unwrap().account;
        assert_eq!(acc_b.username, None);
        assert!(acc_b.unreadable_fields.contains(&"username".to_string()));
        assert_eq!(acc_b.name, format!("[nome ilegível #{id_b}]"));
        assert!(acc_b.unreadable_fields.contains(&"name".to_string()));
        assert_eq!(acc_a.category, None);
        assert_eq!(acc_a.unreadable_fields, vec!["category".to_string()]);
        assert_eq!(acc_a.username.as_deref(), Some("usuario-da-conta-a"), "o campo legítimo continua legível");
        assert_eq!(acc_a.email.as_deref(), Some("a@example.invalid"));
    }

    #[test]
    fn editing_never_wipes_an_unreadable_value_unless_the_user_types_a_new_one() {
        let conn = mem_conn();
        let mut a = input_named("conta-a");
        a.username = Some("usuario".into());
        let id = create(&conn, &a);
        conn.execute("UPDATE accounts SET username = 'enc:v2:AAAA' WHERE id = ?1", [id]).unwrap();
        conn.execute("UPDATE accounts SET name = 'enc:v2:AAAA' WHERE id = ?1", [id]).unwrap();

        // A UI recebeu `username = null` e o nome-marcador; salvar sem mexer mantém o armazenado.
        let mut same = input_named(&format!("[nome ilegível #{id}]"));
        same.username = None;
        update_account_core(&conn, &TEST_DEK, id, &same, validate_input(&same).unwrap()).unwrap();
        assert_eq!(raw_col(&conn, "username", id).as_deref(), Some("enc:v2:AAAA"));
        assert_eq!(raw_col(&conn, "name", id).as_deref(), Some("enc:v2:AAAA"));

        // Digitar um valor novo é uma escolha explícita: substitui e volta a ser legível.
        let mut fixed = input_named("nome-corrigido");
        fixed.username = Some("usuario-novo".into());
        update_account_core(&conn, &TEST_DEK, id, &fixed, validate_input(&fixed).unwrap()).unwrap();
        let listed = &list(&conn, "active")[0].account;
        assert_eq!((listed.name.as_str(), listed.username.as_deref()), ("nome-corrigido", Some("usuario-novo")));
        assert!(listed.unreadable_fields.is_empty());
    }

    #[test]
    fn failure_while_creating_leaves_no_half_written_account() {
        let conn = mem_conn();
        // Sem a tabela de histórico, o ÚLTIMO passo de `create_account_core` falha: a transação
        // inteira (inclusive o INSERT com marcadores vazios e o UPDATE cifrado) precisa desfazer.
        conn.execute("DROP TABLE account_history", []).unwrap();
        let input = input_named("conta-que-vai-falhar");
        let validated = validate_input(&input).unwrap();
        assert!(create_account_core(&conn, &TEST_DEK, &input, validated).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0, "nenhuma linha parcial (nem com marcador vazio) pode sobrar");
    }

    #[test]
    fn history_detail_is_encrypted_and_authenticated_per_row() {
        let conn = mem_conn();
        let id = create(&conn, &input_named("conta"));
        history::insert_history_row(&conn, &TEST_DEK, id, "username_changed", Some("audit-user-7391 → outro")).unwrap();
        history::insert_history_row(&conn, &TEST_DEK, id, "email_changed", Some("segundo detalhe")).unwrap();
        let raw: Vec<Option<String>> = conn
            .prepare("SELECT detail FROM account_history WHERE event != 'created' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(raw.iter().flatten().all(|v| v.starts_with("enc:v2:") && !v.contains("audit-user")));
        let created_detail: Option<String> = conn.query_row("SELECT detail FROM account_history WHERE event = 'created'", [], |r| r.get(0)).unwrap();
        assert_eq!(created_detail, None);

        // copiar o detalhe de uma linha para outra → ilegível, nunca o valor trocado
        conn.execute("UPDATE account_history SET detail = ?1 WHERE event = 'email_changed'", [raw[0].clone().unwrap()]).unwrap();
        let entries = history::list_history_for_test(&conn, &TEST_DEK, id);
        let by_event = |e: &str| entries.iter().find(|x| x.event == e).unwrap().detail.clone();
        assert_eq!(by_event("username_changed").as_deref(), Some("audit-user-7391 → outro"));
        assert_eq!(by_event("email_changed").as_deref(), Some("[detalhe ilegível]"));
    }

    // Backups `.vaultbackup`: novo (v2) e antigo (texto puro) restauram com os mesmos ids e a
    // migração converte o antigo depois.
    #[test]
    fn v2_backup_restores_and_authenticates_with_the_same_dek() {
        let source = mem_conn();
        let mut input = input_named("audit-name-7391");
        input.username = Some("audit-user-7391".into());
        let id = create(&source, &input);
        history::insert_history_row(&source, &TEST_DEK, id, "username_changed", Some("detalhe fictício")).unwrap();

        let restored = crate::commands::backup::clone_via_backup_for_test(&source, "senha-do-backup-123");
        assert_eq!(raw_col(&restored, "username", id), raw_col(&source, "username", id), "o ciphertext viaja byte a byte");
        let listed = &list(&restored, "all")[0].account;
        assert_eq!(listed.username.as_deref(), Some("audit-user-7391"));
        assert!(listed.unreadable_fields.is_empty());
        let history = history::list_history_for_test(&restored, &TEST_DEK, id);
        assert!(history.iter().any(|h| h.detail.as_deref() == Some("detalhe fictício")));
    }

    #[test]
    fn old_plaintext_backup_restores_and_is_migrated_afterwards() {
        let source = mem_conn();
        source
            .execute("INSERT INTO accounts (name, username, email, created_at, updated_at) VALUES ('audit-name-7391', 'audit-user-7391', 'audit-email-7391@example.invalid', 'now', 'now')", [])
            .unwrap();
        source.execute("INSERT INTO account_history (account_id, event, detail, created_at) VALUES (1, 'username_changed', 'audit-history-detail-7391', 'now')", []).unwrap();

        let restored = crate::commands::backup::clone_via_backup_for_test(&source, "senha-do-backup-123");
        assert_eq!(raw_col(&restored, "username", 1).as_deref(), Some("audit-user-7391"), "o backup antigo restaura como estava");
        assert_eq!(list(&restored, "all")[0].account.username.as_deref(), Some("audit-user-7391"), "e já é legível antes da migração");

        let report = crate::migration::migrate_metadata_v2(&restored, &TEST_DEK).unwrap();
        assert_eq!(report.migrated, 4);
        assert!(raw_col(&restored, "username", 1).unwrap().starts_with("enc:v2:"));
        assert_eq!(list(&restored, "all")[0].account.username.as_deref(), Some("audit-user-7391"));
    }
}

#[cfg(test)]
mod account_dates_tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    const DEK: [u8; 32] = [7u8; 32];

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        conn
    }

    fn input(name: &str) -> SaveAccountInput {
        SaveAccountInput {
            name: name.to_string(),
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
            last_login_at: None,
            preserve_fields: vec![],
        }
    }

    fn create(conn: &Connection, input: &SaveAccountInput) -> i64 {
        create_account_core(conn, &DEK, input, validate_input(input).unwrap()).unwrap()
    }

    fn update(conn: &Connection, id: i64, input: &SaveAccountInput) {
        update_account_core(conn, &DEK, id, input, validate_input(input).unwrap()).unwrap();
    }

    fn only_account(conn: &Connection) -> Account {
        list_accounts_core(conn, &DEK, "active").unwrap().remove(0).account
    }

    fn raw(conn: &Connection, column: &str, id: i64) -> Option<String> {
        conn.query_row(&format!("SELECT {column} FROM accounts WHERE id = ?1"), [id], |r| r.get(0)).unwrap()
    }

    #[test]
    fn new_and_legacy_accounts_have_no_dates_and_no_badge() {
        let conn = conn();
        conn.execute("INSERT INTO accounts (name, created_at, updated_at) VALUES ('legada', 'then', 'then')", []).unwrap();
        let a = only_account(&conn);
        assert_eq!((a.last_login_at, a.update_confirmed_at, a.update_expires_at, a.update_badge.as_str()), (None, None, None, "none"));
    }

    #[test]
    fn last_login_is_stored_encrypted_and_is_distinct_from_created_and_updated() {
        let conn = conn();
        let mut i = input("conta");
        i.last_login_at = Some("2026-02-10".to_string());
        let id = create(&conn, &i);
        let stored = raw(&conn, "last_login_at", id).unwrap();
        assert!(stored.starts_with(crypto::FIELD_PREFIX_V2), "dado do usuário: criptografado como metadado");
        assert!(!stored.contains("2026-02-10"));
        let a = only_account(&conn);
        assert_eq!(a.last_login_at.as_deref(), Some("2026-02-10"));
        assert_ne!(a.last_login_at.as_deref(), Some(a.created_at.as_str()));
        assert_ne!(a.last_login_at.as_deref(), Some(a.updated_at.as_str()));
        // Copiar o valor cifrado para outra coluna/linha não autentica.
        assert!(crypto::decrypt_field(&DEK, "accounts", "category", id, &stored).is_err());
    }

    #[test]
    fn invalid_or_future_last_login_is_rejected_by_validation() {
        let mut i = input("conta");
        i.last_login_at = Some("ontem".to_string());
        assert!(validate_input(&i).is_err());
        i.last_login_at = Some((Utc::now() + Duration::days(30)).format("%Y-%m-%d").to_string());
        assert!(validate_input(&i).is_err());
        i.last_login_at = Some(String::new());
        assert!(validate_input(&i).unwrap().last_login_at.is_none(), "vazio = sem data");
    }

    #[test]
    fn clearing_the_last_login_date_works() {
        let conn = conn();
        let mut i = input("conta");
        i.last_login_at = Some("2026-02-10".to_string());
        let id = create(&conn, &i);
        i.last_login_at = None;
        update(&conn, id, &i);
        assert_eq!(only_account(&conn).last_login_at, None);
        assert_eq!(raw(&conn, "last_login_at", id), None);
    }

    #[test]
    fn marking_as_updated_sets_only_the_confirmation_and_logs_history() {
        let conn = conn();
        let mut i = input("conta");
        i.last_login_at = Some("2026-02-10".to_string());
        let id = create(&conn, &i);
        let before = only_account(&conn);

        let now = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let stamp = mark_account_updated_core(&conn, &DEK, id, now).unwrap();
        assert_eq!(stamp, "2026-03-01T12:00:00Z");

        let after = only_account(&conn);
        assert_eq!(after.update_confirmed_at.as_deref(), Some("2026-03-01T12:00:00+00:00"));
        assert_eq!(after.updated_at, before.updated_at, "confirmar atualização não é editar a conta");
        assert_eq!(after.last_login_at, before.last_login_at, "e não inventa um login");
        let events: Vec<String> = conn
            .prepare("SELECT event FROM account_history WHERE account_id = ?1 ORDER BY id")
            .unwrap()
            .query_map([id], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(events, vec!["created".to_string(), "update_confirmed".to_string()]);
    }

    #[test]
    fn editing_or_listing_an_account_never_renews_or_creates_the_confirmation() {
        let conn = conn();
        let id = create(&conn, &input("conta"));
        // Sem confirmação: editar e listar muitas vezes não cria uma.
        for n in 0..3 {
            let mut i = input(&format!("conta editada {n}"));
            i.last_login_at = Some("2026-02-10".to_string());
            update(&conn, id, &i);
            let _ = list_accounts_core(&conn, &DEK, "all").unwrap();
        }
        assert_eq!(raw(&conn, "update_confirmed_at", id), None);

        // Com confirmação antiga: editar/listar não a renova.
        let old = (Utc::now() - Duration::days(80)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        conn.execute("UPDATE accounts SET update_confirmed_at = ?1 WHERE id = ?2", params![old, id]).unwrap();
        update(&conn, id, &input("outra edição"));
        let _ = list_accounts_core(&conn, &DEK, "active").unwrap();
        assert_eq!(raw(&conn, "update_confirmed_at", id), Some(old));
    }

    #[test]
    fn badge_state_follows_the_ninety_day_window_and_hides_bad_or_future_dates() {
        let conn = conn();
        let id = create(&conn, &input("conta"));
        let set = |value: Option<String>| conn.execute("UPDATE accounts SET update_confirmed_at = ?1 WHERE id = ?2", params![value, id]).unwrap();
        let badge = || only_account(&conn).update_badge;
        let stamp = |d: Duration| (Utc::now() + d).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        set(Some(stamp(-Duration::days(10))));
        assert_eq!(badge(), "valid");
        set(Some(stamp(-Duration::days(89))));
        assert_eq!(badge(), "valid");
        set(Some(stamp(-Duration::days(91))));
        assert_eq!(badge(), "expired");
        set(Some("lixo".to_string()));
        assert_eq!(badge(), "none");
        assert_eq!(only_account(&conn).update_confirmed_at, None, "data ilegível nunca é repassada como válida");
        set(Some(stamp(Duration::days(30))));
        assert_eq!(badge(), "none", "data no futuro de forma inconsistente");
        set(None);
        assert_eq!(badge(), "none");
    }

    #[test]
    fn marking_a_missing_or_trashed_account_fails_without_side_effects() {
        let conn = conn();
        assert!(mark_account_updated_core(&conn, &DEK, 999, Utc::now()).is_err());
        let id = create(&conn, &input("conta"));
        conn.execute("UPDATE accounts SET deleted_at = 'x' WHERE id = ?1", [id]).unwrap();
        assert!(mark_account_updated_core(&conn, &DEK, id, Utc::now()).is_err());
        assert_eq!(raw(&conn, "update_confirmed_at", id), None);
        let history: i64 = conn.query_row("SELECT COUNT(*) FROM account_history WHERE event = 'update_confirmed'", [], |r| r.get(0)).unwrap();
        assert_eq!(history, 0);
    }

    #[test]
    fn a_failure_while_marking_leaves_no_partial_change() {
        let conn = conn();
        let id = create(&conn, &input("conta"));
        // Faz o INSERT do histórico falhar: a confirmação precisa ser desfeita junto.
        conn.execute_batch("CREATE TRIGGER boom BEFORE INSERT ON account_history BEGIN SELECT RAISE(ABORT, 'falha simulada'); END;").unwrap();
        assert!(mark_account_updated_core(&conn, &DEK, id, Utc::now()).is_err());
        conn.execute_batch("DROP TRIGGER boom").unwrap();
        assert_eq!(raw(&conn, "update_confirmed_at", id), None);
    }

    #[test]
    fn metadata_migration_encrypts_a_plaintext_last_login_value() {
        let conn = conn();
        let id = create(&conn, &input("conta"));
        conn.execute("UPDATE accounts SET last_login_at = '2026-01-05' WHERE id = ?1", [id]).unwrap();
        let report = crate::migration::migrate_metadata_v2(&conn, &DEK).unwrap();
        assert!(report.migrated >= 1);
        assert!(raw(&conn, "last_login_at", id).unwrap().starts_with(crypto::FIELD_PREFIX_V2));
        assert_eq!(only_account(&conn).last_login_at.as_deref(), Some("2026-01-05"));
    }
}
