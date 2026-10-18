use crate::commands::tags::{self, Tag};
use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tauri::{AppHandle, State};

const NAME_MAX: usize = 200;
const DESCRIPTION_MAX: usize = 2000;
const NOTES_MAX: usize = 20_000;
const COLOR_MAX: usize = 32;

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

#[derive(Serialize, Clone)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub avatar_image_id: Option<i64>,
    pub favorite: i64,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub sort_order: i64,
}

#[derive(Serialize)]
pub struct ProjectWithRelations {
    #[serde(flatten)]
    pub project: Project,
    pub tags: Vec<Tag>,
    #[serde(rename = "accountsCount")]
    pub accounts_count: i64,
    #[serde(rename = "platformNames")]
    pub platform_names: Vec<String>,
}

#[derive(Deserialize)]
pub struct ProjectFormValues {
    // O frontend envia `id` no mesmo objeto usado para decidir create/update (`values.id ?
    // updateProject(values.id, values) : createProject(values)`), mas o command já recebe o id
    // separadamente quando é uma atualização — este campo só existe para o `serde` não rejeitar
    // o payload por causa de um campo extra.
    #[allow(dead_code)]
    pub id: Option<i64>,
    pub name: String,
    pub description: String,
    pub color: Option<String>,
    pub avatar_image_id: Option<i64>,
    pub favorite: bool,
    pub notes: String,
    pub tags: Vec<String>,
}

fn map_project(row: &rusqlite::Row) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        color: row.get(3)?,
        avatar_image_id: row.get(4)?,
        favorite: row.get(5)?,
        notes: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
        sort_order: row.get(9)?,
    })
}

const PROJECT_COLUMNS: &str = "id, name, description, color, avatar_image_id, favorite, notes, created_at, updated_at, sort_order";

#[tauri::command]
pub fn list_projects_with_relations(app: AppHandle, state: State<VaultState>) -> Result<Vec<ProjectWithRelations>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;

    let projects: Vec<Project> = {
        let sql = format!("SELECT {PROJECT_COLUMNS} FROM projects ORDER BY sort_order ASC, name ASC");
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mapped = stmt.query_map([], map_project).map_err(|e| e.to_string())?;
        mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
    };

    let mut tags_by_project: HashMap<i64, Vec<Tag>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT pt.project_id, t.id, t.name FROM project_tags pt JOIN tags t ON t.id = pt.tag_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, Tag { id: row.get(1)?, name: row.get(2)? })))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        for (project_id, tag) in rows {
            tags_by_project.entry(project_id).or_default().push(tag);
        }
    }

    let mut count_by_project: HashMap<i64, i64> = HashMap::new();
    let mut platforms_by_project: HashMap<i64, HashSet<String>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT ap.project_id, ap.account_id, p.name FROM account_projects ap \
                 JOIN accounts a ON a.id = ap.account_id \
                 LEFT JOIN platforms p ON p.id = a.platform_id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(2)?)))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        for (project_id, platform_name) in rows {
            *count_by_project.entry(project_id).or_insert(0) += 1;
            if let Some(name) = platform_name {
                platforms_by_project.entry(project_id).or_default().insert(name);
            }
        }
    }

    Ok(projects
        .into_iter()
        .map(|project| {
            let id = project.id;
            ProjectWithRelations {
                tags: tags_by_project.remove(&id).unwrap_or_default(),
                accounts_count: *count_by_project.get(&id).unwrap_or(&0),
                platform_names: platforms_by_project.remove(&id).map(|s| s.into_iter().collect()).unwrap_or_default(),
                project,
            }
        })
        .collect())
}

struct ValidatedProjectInput {
    name: String,
    description: Option<String>,
    color: Option<String>,
    notes: Option<String>,
}

fn validate_input(input: &ProjectFormValues) -> Result<ValidatedProjectInput, String> {
    let name = validate::trim_required(&input.name, "O nome do projeto", NAME_MAX)?;
    let description = validate::trim_optional(&input.description, DESCRIPTION_MAX, "A descrição")?;
    let notes = validate::trim_optional(&input.notes, NOTES_MAX, "As observações")?;
    let color = match &input.color {
        Some(v) => validate::trim_optional(v, COLOR_MAX, "A cor")?,
        None => None,
    };
    Ok(ValidatedProjectInput { name, description, color, notes })
}

#[tauri::command]
pub fn create_project(app: AppHandle, state: State<VaultState>, input: ProjectFormValues) -> Result<i64, String> {
    require_unlocked(&state)?;
    let v = validate_input(&input)?;
    let conn = db::open(&app)?;
    let now = db::now_iso();
    let next_order: i64 = conn
        .query_row("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM projects", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO projects (name, description, color, avatar_image_id, favorite, notes, created_at, updated_at, sort_order) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![v.name, v.description, v.color, input.avatar_image_id, input.favorite as i64, v.notes, now, now, next_order],
    )
    .map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    tags::sync_tags(&conn, "project_tags", "project_id", id, &input.tags)?;
    Ok(id)
}

#[tauri::command]
pub fn reorder_projects(app: AppHandle, state: State<VaultState>, ordered_ids: Vec<i64>) -> Result<(), String> {
    require_unlocked(&state)?;
    for id in &ordered_ids {
        validate::positive_id(*id, "id")?;
    }
    let mut conn = db::open(&app)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    for (index, id) in ordered_ids.iter().enumerate() {
        tx.execute("UPDATE projects SET sort_order = ?1 WHERE id = ?2", params![index as i64, id])
            .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn update_project(app: AppHandle, state: State<VaultState>, id: i64, input: ProjectFormValues) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let v = validate_input(&input)?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE projects SET name = ?1, description = ?2, color = ?3, avatar_image_id = ?4, favorite = ?5, notes = ?6, updated_at = ?7 \
         WHERE id = ?8",
        params![v.name, v.description, v.color, input.avatar_image_id, input.favorite as i64, v.notes, db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    tags::sync_tags(&conn, "project_tags", "project_id", id, &input.tags)?;
    Ok(())
}

#[tauri::command]
pub fn delete_project(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("DELETE FROM projects WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn toggle_project_favorite(app: AppHandle, state: State<VaultState>, id: i64, favorite: bool) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute(
        "UPDATE projects SET favorite = ?1, updated_at = ?2 WHERE id = ?3",
        params![favorite as i64, db::now_iso(), id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
