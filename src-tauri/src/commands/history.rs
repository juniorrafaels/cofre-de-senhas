use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, Connection};
use serde::Serialize;
use tauri::{AppHandle, State};

const DETAIL_MAX: usize = 2000;

/// Allowlist fechada dos eventos de histórico que o app realmente gera (ver `App.tsx`,
/// `logAccountChanges`). Uma WebView comprometida não pode usar este command para gravar
/// eventos arbitrários/spam/desinformação no histórico de uma conta — só os eventos que a UI
/// legítima já usa.
const ALLOWED_EVENTS: &[&str] = &[
    "created",
    "archived",
    "restored",
    "username_changed",
    "email_changed",
    "password_changed",
    "platform_changed",
    "status_changed",
    "avatar_changed",
    "tags_changed",
    "project_added",
    "project_removed",
    "two_factor_enabled",
    "two_factor_disabled",
];

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

#[derive(Serialize)]
pub struct AccountHistoryEntry {
    pub id: i64,
    pub account_id: i64,
    pub event: String,
    pub detail: Option<String>,
    pub created_at: String,
}

/// Usada tanto pelo command público `log_account_history` quanto internamente por
/// `commands::accounts` (ex.: ao criar/arquivar/restaurar uma conta).
pub fn insert_history_row(conn: &Connection, account_id: i64, event: &str, detail: Option<&str>) -> Result<(), String> {
    validate::positive_id(account_id, "account_id")?;
    let event = validate::one_of(event, ALLOWED_EVENTS, "O evento de histórico")?;
    if let Some(d) = detail {
        validate::max_len(d, DETAIL_MAX, "O detalhe do histórico")?;
    }
    conn.execute(
        "INSERT INTO account_history (account_id, event, detail, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![account_id, event, detail, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn log_account_history(
    app: AppHandle,
    state: State<VaultState>,
    account_id: i64,
    event: String,
    detail: Option<String>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    insert_history_row(&conn, account_id, &event, detail.as_deref())
}

#[tauri::command]
pub fn list_account_history(app: AppHandle, state: State<VaultState>, account_id: i64) -> Result<Vec<AccountHistoryEntry>, String> {
    require_unlocked(&state)?;
    validate::positive_id(account_id, "account_id")?;
    let conn = db::open(&app)?;
    let mut stmt = conn
        .prepare("SELECT id, account_id, event, detail, created_at FROM account_history WHERE account_id = ?1 ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let mapped = stmt
        .query_map([account_id], |row| {
            Ok(AccountHistoryEntry {
                id: row.get(0)?,
                account_id: row.get(1)?,
                event: row.get(2)?,
                detail: row.get(3)?,
                created_at: row.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db_with_account() -> (Connection, i64) {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        conn.execute("INSERT INTO accounts (name, created_at, updated_at) VALUES ('a', 'now', 'now')", [])
            .unwrap();
        let id = conn.last_insert_rowid();
        (conn, id)
    }

    // Regressão de segurança (SECURITY_AUDIT_PHASE_3.md, seção "IPC/Tauri Commands"): uma
    // WebView comprometida não pode usar este command para gravar eventos arbitrários no
    // histórico de uma conta — só a allowlist fechada de eventos que a UI legítima já gera.
    #[test]
    fn rejects_events_outside_the_allowlist() {
        let (conn, account_id) = memory_db_with_account();
        assert!(insert_history_row(&conn, account_id, "created", None).is_ok());
        assert!(insert_history_row(&conn, account_id, "'; DROP TABLE accounts;--", None).is_err());
        assert!(insert_history_row(&conn, account_id, "totally_made_up_event", None).is_err());
    }

    #[test]
    fn rejects_invalid_account_id() {
        let (conn, _) = memory_db_with_account();
        assert!(insert_history_row(&conn, 0, "created", None).is_err());
        assert!(insert_history_row(&conn, -5, "created", None).is_err());
    }

    #[test]
    fn rejects_oversized_detail() {
        let (conn, account_id) = memory_db_with_account();
        let huge = "x".repeat(DETAIL_MAX + 1);
        assert!(insert_history_row(&conn, account_id, "created", Some(&huge)).is_err());
    }
}
