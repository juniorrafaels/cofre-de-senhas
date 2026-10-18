use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

const NAME_MAX: usize = 200;
const URL_MAX: usize = 2048;
const ICON_MAX: usize = 32;

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

#[derive(Serialize)]
pub struct Platform {
    pub id: i64,
    pub name: String,
    pub icon: Option<String>,
    pub login_url: Option<String>,
    pub website_url: Option<String>,
    pub is_custom: i64,
    pub logo_image_id: Option<i64>,
    pub created_at: String,
    pub sort_order: i64,
    /// Identificador estável da plataforma oficial (ver `db::PLATFORM_SEEDS`); `None` para
    /// qualquer plataforma criada pelo usuário. Nunca é definido por `create_platform`/
    /// `update_platform` — só a semeadura de defaults grava este campo.
    pub system_key: Option<String>,
}

#[derive(Deserialize)]
pub struct PlatformFormInput {
    pub name: String,
    pub icon: Option<String>,
    pub login_url: Option<String>,
    pub website_url: Option<String>,
    pub logo_image_id: Option<i64>,
}

fn map_platform(row: &rusqlite::Row) -> rusqlite::Result<Platform> {
    Ok(Platform {
        id: row.get(0)?,
        name: row.get(1)?,
        icon: row.get(2)?,
        login_url: row.get(3)?,
        website_url: row.get(4)?,
        is_custom: row.get(5)?,
        created_at: row.get(6)?,
        logo_image_id: row.get(7)?,
        sort_order: row.get(8)?,
        system_key: row.get(9)?,
    })
}

struct ValidatedPlatformInput {
    name: String,
    icon: Option<String>,
    login_url: Option<String>,
    website_url: Option<String>,
}

fn validate_input(input: &PlatformFormInput) -> Result<ValidatedPlatformInput, String> {
    let name = validate::trim_required(&input.name, "O nome da plataforma", NAME_MAX)?;
    let icon = match &input.icon {
        Some(v) => validate::trim_optional(v, ICON_MAX, "O ícone")?,
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
    Ok(ValidatedPlatformInput { name, icon, login_url, website_url })
}

#[tauri::command]
pub fn list_platforms(app: AppHandle, state: State<VaultState>) -> Result<Vec<Platform>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, icon, login_url, website_url, is_custom, created_at, logo_image_id, sort_order, system_key \
             FROM platforms ORDER BY sort_order ASC, is_custom ASC, name ASC",
        )
        .map_err(|e| e.to_string())?;
    let mapped = stmt.query_map([], map_platform).map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn create_platform(app: AppHandle, state: State<VaultState>, input: PlatformFormInput) -> Result<i64, String> {
    require_unlocked(&state)?;
    let v = validate_input(&input)?;
    let conn = db::open(&app)?;
    let next_order: i64 = conn
        .query_row("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM platforms", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO platforms (name, icon, login_url, website_url, logo_image_id, is_custom, created_at, sort_order) \
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)",
        params![v.name, v.icon, v.login_url, v.website_url, input.logo_image_id, db::now_iso(), next_order],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

#[tauri::command]
pub fn reorder_platforms(app: AppHandle, state: State<VaultState>, ordered_ids: Vec<i64>) -> Result<(), String> {
    require_unlocked(&state)?;
    for id in &ordered_ids {
        validate::positive_id(*id, "id")?;
    }
    let mut conn = db::open(&app)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for (index, id) in ordered_ids.iter().enumerate() {
        tx.execute("UPDATE platforms SET sort_order = ?1 WHERE id = ?2", params![index as i64, id])
            .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn update_platform(app: AppHandle, state: State<VaultState>, id: i64, input: PlatformFormInput) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let v = validate_input(&input)?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE platforms SET name = ?1, icon = ?2, login_url = ?3, website_url = ?4, logo_image_id = ?5 WHERE id = ?6",
        params![v.name, v.icon, v.login_url, v.website_url, input.logo_image_id, id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn delete_platform(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    // Se for uma plataforma oficial (tem system_key), registra a exclusão antes de apagar a
    // linha — sem isso, a próxima inicialização recriaria a plataforma que o usuário decidiu
    // remover (ver db::mark_platform_seed_removed e seção 18 do pedido de ajuste).
    let system_key: Option<String> = conn
        .query_row("SELECT system_key FROM platforms WHERE id = ?1", [id], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM platforms WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    if let Some(key) = system_key {
        db::mark_platform_seed_removed(&conn, &key)?;
    }
    Ok(())
}

#[tauri::command]
pub fn reassign_accounts_platform(
    app: AppHandle,
    state: State<VaultState>,
    from_platform_id: i64,
    to_platform_id: Option<i64>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(from_platform_id, "from_platform_id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE accounts SET platform_id = ?1, updated_at = ?2 WHERE platform_id = ?3",
        params![to_platform_id, db::now_iso(), from_platform_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
