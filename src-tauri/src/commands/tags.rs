use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashMap;
use tauri::{AppHandle, State};

const NAME_MAX: usize = 100;

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

#[derive(Serialize)]
pub struct Tag {
    pub id: i64,
    pub name: String,
}

#[derive(Serialize)]
pub struct TagWithUsage {
    pub id: i64,
    pub name: String,
    #[serde(rename = "accountsCount")]
    pub accounts_count: i64,
    #[serde(rename = "projectsCount")]
    pub projects_count: i64,
}

fn normalize_name(name: &str) -> Result<String, String> {
    let trimmed = validate::trim_required(name, "O nome da tag", NAME_MAX)?;
    Ok(trimmed.to_lowercase())
}

#[tauri::command]
pub fn list_tags(app: AppHandle, state: State<VaultState>) -> Result<Vec<Tag>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let mut stmt = conn.prepare("SELECT id, name FROM tags ORDER BY name ASC").map_err(|e| e.to_string())?;
    let mapped = stmt.query_map([], |row| Ok(Tag { id: row.get(0)?, name: row.get(1)? })).map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_tags_with_usage(app: AppHandle, state: State<VaultState>) -> Result<Vec<TagWithUsage>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;

    let tags: Vec<Tag> = {
        let mut stmt = conn.prepare("SELECT id, name FROM tags ORDER BY name ASC").map_err(|e| e.to_string())?;
        let mapped = stmt.query_map([], |row| Ok(Tag { id: row.get(0)?, name: row.get(1)? })).map_err(|e| e.to_string())?;
        mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
    };

    let account_counts = count_by_tag(&conn, "account_tags")?;
    let project_counts = count_by_tag(&conn, "project_tags")?;

    Ok(tags
        .into_iter()
        .map(|tag| TagWithUsage {
            accounts_count: *account_counts.get(&tag.id).unwrap_or(&0),
            projects_count: *project_counts.get(&tag.id).unwrap_or(&0),
            id: tag.id,
            name: tag.name,
        })
        .collect())
}

fn count_by_tag(conn: &Connection, join_table: &str) -> Result<HashMap<i64, i64>, String> {
    // `join_table` nunca vem da WebView — é um literal fixo passado pelas duas chamadas acima
    // (nunca uma string de usuário), então a interpolação aqui não é injeção de SQL.
    let sql = format!("SELECT tag_id, COUNT(*) as count FROM {join_table} GROUP BY tag_id");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().collect())
}

/// Garante que cada nome em `names` tenha uma linha em `tags`, criando as que faltarem, e
/// devolve os IDs correspondentes. Usada internamente por `create_account`/`update_account`/
/// `create_project`/`update_project` — nunca exposta diretamente como command (a WebView não
/// precisa de um "upsert de tags" genérico, só de contas/projetos com uma lista de nomes).
pub fn ensure_tag_ids(conn: &Connection, names: &[String]) -> Result<Vec<i64>, String> {
    let mut ids = Vec::with_capacity(names.len());
    for raw in names {
        let name = match normalize_name(raw) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if name.is_empty() {
            continue;
        }
        let existing: Option<i64> = conn
            .query_row("SELECT id FROM tags WHERE name = ?1", [&name], |row| row.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let id = match existing {
            Some(id) => id,
            None => {
                conn.execute("INSERT INTO tags (name) VALUES (?1)", [&name]).map_err(|e| e.to_string())?;
                conn.last_insert_rowid()
            }
        };
        ids.push(id);
    }
    Ok(ids)
}

#[tauri::command]
pub fn create_tag(app: AppHandle, state: State<VaultState>, name: String) -> Result<i64, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let ids = ensure_tag_ids(&conn, std::slice::from_ref(&name))?;
    ids.first().copied().ok_or_else(|| "Nome de tag inválido.".to_string())
}

#[tauri::command]
pub fn rename_tag(app: AppHandle, state: State<VaultState>, id: i64, name: String) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let normalized = normalize_name(&name)?;
    let conn = db::open(&app)?;
    conn.execute("UPDATE tags SET name = ?1 WHERE id = ?2", params![normalized, id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn delete_tag(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("DELETE FROM tags WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

/// Substitui completamente o conjunto de tags associadas a uma conta/projeto por `tag_names`.
/// Compartilhado por `accounts.rs` e `projects.rs`.
pub fn sync_tags(conn: &Connection, join_table: &str, id_column: &str, entity_id: i64, tag_names: &[String]) -> Result<(), String> {
    let tag_ids = ensure_tag_ids(conn, tag_names)?;
    let delete_sql = format!("DELETE FROM {join_table} WHERE {id_column} = ?1");
    conn.execute(&delete_sql, [entity_id]).map_err(|e| e.to_string())?;
    let insert_sql = format!("INSERT OR IGNORE INTO {join_table} ({id_column}, tag_id) VALUES (?1, ?2)");
    for tag_id in tag_ids {
        conn.execute(&insert_sql, params![entity_id, tag_id]).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn ensure_tag_ids_deduplicates_by_normalized_name() {
        let conn = memory_db();
        let ids = ensure_tag_ids(&conn, &["Work".to_string(), " work ".to_string(), "WORK".to_string()]).unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], ids[1]);
        assert_eq!(ids[1], ids[2]);
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM tags", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn ensure_tag_ids_skips_blank_names() {
        let conn = memory_db();
        let ids = ensure_tag_ids(&conn, &["   ".to_string(), "real".to_string()]).unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn sync_tags_replaces_the_full_set_each_call() {
        let conn = memory_db();
        conn.execute(
            "INSERT INTO accounts (name, created_at, updated_at) VALUES ('a', 'now', 'now')",
            [],
        )
        .unwrap();
        let account_id = conn.last_insert_rowid();

        sync_tags(&conn, "account_tags", "account_id", account_id, &["one".to_string(), "two".to_string()]).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM account_tags WHERE account_id = ?1", [account_id], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);

        sync_tags(&conn, "account_tags", "account_id", account_id, &["three".to_string()]).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM account_tags WHERE account_id = ?1", [account_id], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
