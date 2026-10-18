use crate::commands::clipboard;
use crate::crypto;
use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, State};

const NAME_MAX: usize = 200;
// Valor pode ser texto puro (não sensível, inclusive `longtext`) — o Rust cifra internamente
// quando `is_sensitive`, então este teto vale para o texto puro recebido da WebView.
const VALUE_MAX: usize = 50_000;

const PROPERTY_TYPES: &[&str] = &["text", "number", "phone", "email", "url", "date", "boolean", "longtext"];

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

fn require_dek(state: &State<VaultState>) -> Result<[u8; 32], String> {
    state.with_dek(|dek| *dek).ok_or_else(|| "O cofre está bloqueado.".to_string())
}

#[derive(Serialize)]
pub struct PropertyDefinition {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub property_type: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct AccountPropertyWithDefinition {
    pub id: i64,
    pub account_id: i64,
    pub definition_id: i64,
    /// Fase 4: para propriedades sensíveis, este campo é sempre `null` na listagem — o ciphertext
    /// nunca é enviado à WebView. Presença é sinalizada por `has_value`; o valor real só chega
    /// via `reveal_sensitive_property`/`copy_sensitive_property`, por ID. Para não sensíveis,
    /// continua sendo o texto puro normal (nunca foi segredo).
    pub value: Option<String>,
    pub has_value: bool,
    pub is_sensitive: i64,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    #[serde(rename = "type")]
    pub property_type: String,
}

#[tauri::command]
pub fn list_property_definitions(app: AppHandle, state: State<VaultState>) -> Result<Vec<PropertyDefinition>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let mut stmt = conn
        .prepare("SELECT id, name, type, created_at FROM custom_property_definitions ORDER BY name ASC")
        .map_err(|e| e.to_string())?;
    let mapped = stmt
        .query_map([], |row| {
            Ok(PropertyDefinition { id: row.get(0)?, name: row.get(1)?, property_type: row.get(2)?, created_at: row.get(3)? })
        })
        .map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn ensure_property_definition(
    app: AppHandle,
    state: State<VaultState>,
    name: String,
    property_type: String,
) -> Result<i64, String> {
    require_unlocked(&state)?;
    let name = validate::trim_required(&name, "O nome da propriedade", NAME_MAX)?;
    let property_type = validate::one_of(&property_type, PROPERTY_TYPES, "O tipo da propriedade")?;

    let conn = db::open(&app)?;
    let existing: Option<i64> = conn
        .query_row("SELECT id FROM custom_property_definitions WHERE name = ?1", [&name], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO custom_property_definitions (name, type, created_at) VALUES (?1, ?2, ?3)",
        params![name, property_type, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

#[tauri::command]
pub fn list_account_properties(app: AppHandle, state: State<VaultState>, account_id: i64) -> Result<Vec<AccountPropertyWithDefinition>, String> {
    require_unlocked(&state)?;
    validate::positive_id(account_id, "account_id")?;
    let conn = db::open(&app)?;
    let mut stmt = conn
        .prepare(
            "SELECT ap.id, ap.account_id, ap.definition_id, ap.value, ap.is_sensitive, ap.created_at, ap.updated_at, \
                    d.name, d.type \
             FROM account_properties ap JOIN custom_property_definitions d ON d.id = ap.definition_id \
             WHERE ap.account_id = ?1 ORDER BY ap.created_at ASC",
        )
        .map_err(|e| e.to_string())?;
    let mapped = stmt
        .query_map([account_id], |row| {
            let raw_value: Option<String> = row.get(3)?;
            let is_sensitive: i64 = row.get(4)?;
            let has_value = raw_value.is_some() && !raw_value.as_deref().unwrap_or_default().is_empty();
            let value = if is_sensitive != 0 { None } else { raw_value };
            Ok(AccountPropertyWithDefinition {
                id: row.get(0)?,
                account_id: row.get(1)?,
                definition_id: row.get(2)?,
                value,
                has_value,
                is_sensitive,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                name: row.get(7)?,
                property_type: row.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn create_account_property(
    app: AppHandle,
    state: State<VaultState>,
    account_id: i64,
    definition_id: i64,
    value: String,
    is_sensitive: bool,
) -> Result<i64, String> {
    validate::positive_id(account_id, "account_id")?;
    validate::positive_id(definition_id, "definition_id")?;
    validate::max_len(&value, VALUE_MAX, "O valor da propriedade")?;

    let stored_value = if is_sensitive {
        let dek = require_dek(&state)?;
        crypto::encrypt_to_base64(&dek, &value)?
    } else {
        require_unlocked(&state)?;
        value
    };

    let conn = db::open(&app)?;
    let now = db::now_iso();
    conn.execute(
        "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![account_id, definition_id, stored_value, is_sensitive as i64, now, now],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

/// Confirma que `property_id` pertence a `account_id` antes de qualquer leitura/escrita — sem
/// isso, um ID de propriedade de outra conta poderia ser manipulado diretamente via IPC (Fase 4,
/// SECURITY_AUDIT_PHASE_4.md, seção 10 do pedido original). Retorna `is_sensitive` da linha.
fn verify_property_ownership(conn: &Connection, account_id: i64, property_id: i64) -> Result<i64, String> {
    let row: Option<(i64, i64)> = conn
        .query_row("SELECT account_id, is_sensitive FROM account_properties WHERE id = ?1", [property_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(|e| e.to_string())?;
    match row {
        Some((owner_id, is_sensitive)) if owner_id == account_id => Ok(is_sensitive),
        // Erro genérico tanto para "não existe" quanto para "existe mas é de outra conta" — não
        // dá pista a uma WebView comprometida sobre qual dos dois casos ocorreu.
        _ => Err("Propriedade não encontrada.".to_string()),
    }
}

#[tauri::command]
pub fn update_account_property(
    app: AppHandle,
    state: State<VaultState>,
    account_id: i64,
    id: i64,
    value: String,
    is_sensitive: bool,
) -> Result<(), String> {
    validate::positive_id(account_id, "account_id")?;
    validate::positive_id(id, "id")?;
    validate::max_len(&value, VALUE_MAX, "O valor da propriedade")?;

    let conn = db::open(&app)?;
    verify_property_ownership(&conn, account_id, id)?;

    let stored_value = if is_sensitive {
        let dek = require_dek(&state)?;
        crypto::encrypt_to_base64(&dek, &value)?
    } else {
        require_unlocked(&state)?;
        value
    };

    conn.execute(
        "UPDATE account_properties SET value = ?1, is_sensitive = ?2, updated_at = ?3 WHERE id = ?4",
        params![stored_value, is_sensitive as i64, db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn delete_account_property(app: AppHandle, state: State<VaultState>, account_id: i64, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(account_id, "account_id")?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    verify_property_ownership(&conn, account_id, id)?;
    conn.execute("DELETE FROM account_properties WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_sensitive_property_ciphertext(conn: &Connection, account_id: i64, property_id: i64) -> Result<String, String> {
    let is_sensitive = verify_property_ownership(conn, account_id, property_id)?;
    if is_sensitive == 0 {
        return Err("Esta propriedade não é sensível.".to_string());
    }
    conn.query_row("SELECT value FROM account_properties WHERE id = ?1", [property_id], |row| row.get(0))
        .map_err(|_| "Propriedade não encontrada.".to_string())
}

/// Revela UMA propriedade sensível de UMA conta específica — substitui o antigo padrão
/// `decrypt_secret(prop.value)`. Sujeito ao rate limiter (mesma razão de `reveal_account_password`).
#[tauri::command]
pub fn reveal_sensitive_property(app: AppHandle, state: State<VaultState>, account_id: i64, property_id: i64) -> Result<String, String> {
    validate::positive_id(account_id, "account_id")?;
    validate::positive_id(property_id, "property_id")?;
    state.reveal_limiter.check_and_record()?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let ciphertext = load_sensitive_property_ciphertext(&conn, account_id, property_id)?;
    crypto::decrypt_from_base64(&dek, &ciphertext)
}

/// Decifra e copia inteiramente no Rust — plaintext nunca atravessa para a WebView.
#[tauri::command]
pub fn copy_sensitive_property(
    app: AppHandle,
    state: State<VaultState>,
    account_id: i64,
    property_id: i64,
    clear_after_seconds: Option<u64>,
) -> Result<(), String> {
    validate::positive_id(account_id, "account_id")?;
    validate::positive_id(property_id, "property_id")?;
    let dek = require_dek(&state)?;
    let conn = db::open(&app)?;
    let ciphertext = load_sensitive_property_ciphertext(&conn, account_id, property_id)?;
    let plaintext = zeroize::Zeroizing::new(crypto::decrypt_from_base64(&dek, &ciphertext)?);
    clipboard::write_secret_and_schedule_clear(&app, plaintext, clear_after_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_conn_with_two_accounts() -> (Connection, i64, i64, i64) {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let now = db::now_iso();
        conn.execute(
            "INSERT INTO accounts (name, status, two_factor_enabled, created_at, updated_at) VALUES ('A', 'active', 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        let account_a = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO accounts (name, status, two_factor_enabled, created_at, updated_at) VALUES ('B', 'active', 0, ?1, ?1)",
            [&now],
        )
        .unwrap();
        let account_b = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO custom_property_definitions (name, type, created_at) VALUES ('API Key', 'text', ?1)",
            [&now],
        )
        .unwrap();
        let definition_id = conn.last_insert_rowid();
        (conn, account_a, account_b, definition_id)
    }

    #[test]
    fn reveal_rejects_property_belonging_to_another_account() {
        let (conn, account_a, account_b, definition_id) = setup_conn_with_two_accounts();
        let dek = [9u8; 32];
        let ciphertext = crypto::encrypt_to_base64(&dek, "XSS_TEST_APIKEY").unwrap();
        let now = db::now_iso();
        conn.execute(
            "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            params![account_a, definition_id, ciphertext, now],
        )
        .unwrap();
        let property_id = conn.last_insert_rowid();

        // A propriedade pertence à conta A — pedir revelação passando a conta B deve falhar.
        assert!(load_sensitive_property_ciphertext(&conn, account_b, property_id).is_err());
        // Passando o account_id correto, funciona.
        assert!(load_sensitive_property_ciphertext(&conn, account_a, property_id).is_ok());
    }

    #[test]
    fn reveal_rejects_non_sensitive_property() {
        let (conn, account_a, _account_b, definition_id) = setup_conn_with_two_accounts();
        let now = db::now_iso();
        conn.execute(
            "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) \
             VALUES (?1, ?2, 'texto simples', 0, ?3, ?3)",
            params![account_a, definition_id, now],
        )
        .unwrap();
        let property_id = conn.last_insert_rowid();

        let err = load_sensitive_property_ciphertext(&conn, account_a, property_id).unwrap_err();
        assert!(err.contains("não é sensível"));
    }

    #[test]
    fn list_never_includes_ciphertext_for_sensitive_properties() {
        let (conn, account_a, _account_b, definition_id) = setup_conn_with_two_accounts();
        let dek = [1u8; 32];
        let ciphertext = crypto::encrypt_to_base64(&dek, "XSS_TEST_APIKEY").unwrap();
        let now = db::now_iso();
        conn.execute(
            "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 1, ?4, ?4)",
            params![account_a, definition_id, ciphertext, now],
        )
        .unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT ap.id, ap.account_id, ap.definition_id, ap.value, ap.is_sensitive, ap.created_at, ap.updated_at, d.name, d.type \
                 FROM account_properties ap JOIN custom_property_definitions d ON d.id = ap.definition_id WHERE ap.account_id = ?1",
            )
            .unwrap();
        let rows: Vec<AccountPropertyWithDefinition> = stmt
            .query_map([account_a], |row| {
                let raw_value: Option<String> = row.get(3)?;
                let is_sensitive: i64 = row.get(4)?;
                let has_value = raw_value.is_some();
                let value = if is_sensitive != 0 { None } else { raw_value };
                Ok(AccountPropertyWithDefinition {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    definition_id: row.get(2)?,
                    value,
                    has_value,
                    is_sensitive,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                    name: row.get(7)?,
                    property_type: row.get(8)?,
                })
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, None, "ciphertext não deveria aparecer na listagem para propriedades sensíveis");
        assert!(rows[0].has_value);
    }
}
