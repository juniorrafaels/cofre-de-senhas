use crate::crypto;
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
    "update_confirmed",
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
///
/// `detail` pode conter dados pessoais (ex.: usuário antigo → novo), então é gravado no formato
/// `enc:v2:` com AAD de (account_history, detail, id da linha). Como o id só existe depois do
/// INSERT, a linha nasce com `detail` NULL e é atualizada dentro de um SAVEPOINT — o texto puro
/// nunca chega ao banco, e uma falha no meio desfaz a linha inteira.
pub fn insert_history_row(conn: &Connection, dek: &[u8; 32], account_id: i64, event: &str, detail: Option<&str>) -> Result<(), String> {
    validate::positive_id(account_id, "account_id")?;
    let event = validate::one_of(event, ALLOWED_EVENTS, "O evento de histórico")?;
    if let Some(d) = detail {
        validate::max_len(d, DETAIL_MAX, "O detalhe do histórico")?;
    }
    conn.execute_batch("SAVEPOINT history_insert").map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        conn.execute(
            "INSERT INTO account_history (account_id, event, detail, created_at) VALUES (?1, ?2, NULL, ?3)",
            params![account_id, event, db::now_iso()],
        )
        .map_err(|e| e.to_string())?;
        if let Some(d) = detail {
            let id = conn.last_insert_rowid();
            let stored = crypto::encrypt_field(dek, "account_history", "detail", id, d)?;
            conn.execute("UPDATE account_history SET detail = ?1 WHERE id = ?2", params![stored, id]).map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => conn.execute_batch("RELEASE history_insert").map_err(|e| e.to_string()),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO history_insert; RELEASE history_insert");
            Err(e)
        }
    }
}

#[tauri::command]
pub fn log_account_history(
    app: AppHandle,
    state: State<VaultState>,
    account_id: i64,
    event: String,
    detail: Option<String>,
) -> Result<(), String> {
    let dek = state.with_dek(|dek| *dek).ok_or_else(|| "O cofre está bloqueado.".to_string())?;
    let conn = db::open(&app)?;
    insert_history_row(&conn, &dek, account_id, &event, detail.as_deref())
}

#[tauri::command]
pub fn list_account_history(app: AppHandle, state: State<VaultState>, account_id: i64) -> Result<Vec<AccountHistoryEntry>, String> {
    let dek = state.with_dek(|dek| *dek).ok_or_else(|| "O cofre está bloqueado.".to_string())?;
    validate::positive_id(account_id, "account_id")?;
    let conn = db::open(&app)?;
    list_history_core(&conn, &dek, account_id)
}

/// Texto mostrado no lugar de um `detail` que não autenticou ou tem versão desconhecida (nunca um
/// valor vazio nem "quase certo").
const UNREADABLE_DETAIL: &str = "[detalhe ilegível]";

fn list_history_core(conn: &Connection, dek: &[u8; 32], account_id: i64) -> Result<Vec<AccountHistoryEntry>, String> {
    let mut stmt = conn
        .prepare("SELECT id, account_id, event, detail, created_at FROM account_history WHERE account_id = ?1 ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let mapped = stmt
        .query_map([account_id], |row| {
            let id: i64 = row.get(0)?;
            let stored: Option<String> = row.get(3)?;
            let detail = stored.map(|s| {
                crypto::decrypt_field(dek, "account_history", "detail", id, &s).unwrap_or_else(|_| UNREADABLE_DETAIL.to_string())
            });
            Ok(AccountHistoryEntry { id, account_id: row.get(1)?, event: row.get(2)?, detail, created_at: row.get(4)? })
        })
        .map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) fn list_history_for_test(conn: &Connection, dek: &[u8; 32], account_id: i64) -> Vec<AccountHistoryEntry> {
    list_history_core(conn, dek, account_id).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DEK: [u8; 32] = [9u8; 32];

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
        assert!(insert_history_row(&conn, &TEST_DEK, account_id, "created", None).is_ok());
        assert!(insert_history_row(&conn, &TEST_DEK, account_id, "'; DROP TABLE accounts;--", None).is_err());
        assert!(insert_history_row(&conn, &TEST_DEK, account_id, "totally_made_up_event", None).is_err());
    }

    #[test]
    fn rejects_invalid_account_id() {
        let (conn, _) = memory_db_with_account();
        assert!(insert_history_row(&conn, &TEST_DEK, 0, "created", None).is_err());
        assert!(insert_history_row(&conn, &TEST_DEK, -5, "created", None).is_err());
    }

    #[test]
    fn rejects_oversized_detail() {
        let (conn, account_id) = memory_db_with_account();
        let huge = "x".repeat(DETAIL_MAX + 1);
        assert!(insert_history_row(&conn, &TEST_DEK, account_id, "created", Some(&huge)).is_err());
    }
}
