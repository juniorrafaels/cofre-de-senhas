use crate::db;
use crate::state::VaultState;
use crate::validate;
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager, State};

const NAME_MAX: usize = 200;
// sha256 em hexadecimal minúsculo: sempre 64 caracteres em [0-9a-f].
const HASH_LEN: usize = 64;

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

#[derive(Serialize)]
pub struct ImportImageResult {
    pub filename: String,
    pub hash: String,
    pub original_name: String,
}

#[derive(Serialize, Clone)]
pub struct ImageRecord {
    pub id: i64,
    pub filename: String,
    pub original_name: Option<String>,
    pub name: Option<String>,
    pub hash: String,
    pub created_at: String,
}

fn map_image(row: &rusqlite::Row) -> rusqlite::Result<ImageRecord> {
    Ok(ImageRecord {
        id: row.get(0)?,
        filename: row.get(1)?,
        original_name: row.get(2)?,
        name: row.get(3)?,
        hash: row.get(4)?,
        created_at: row.get(5)?,
    })
}

const IMAGE_COLUMNS: &str = "id, filename, original_name, name, hash, created_at";

fn is_valid_sha256_hex(hash: &str) -> bool {
    hash.len() == HASH_LEN && hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn images_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "não foi possível resolver o diretório de dados do app".to_string())?
        .join("images");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// `filename` só deve ser o nome gerado por `import_image` (`{sha256}.{ext}`), nunca um path.
/// Rejeita separadores de diretório e ".." para impedir que um chamador escape de `images_dir`
/// (path traversal) e leia/apague arquivos arbitrários do usuário via estes comandos.
fn sanitize_image_filename(filename: &str) -> Result<&str, String> {
    let is_safe = !filename.is_empty()
        && filename != "."
        && filename != ".."
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains(':');
    if is_safe {
        Ok(filename)
    } else {
        Err("Nome de arquivo de imagem inválido.".to_string())
    }
}

#[tauri::command]
pub fn import_image(app: AppHandle, state: State<VaultState>, source_path: String) -> Result<ImportImageResult, String> {
    require_unlocked(&state)?;
    let source = PathBuf::from(&source_path);
    let bytes = fs::read(&source).map_err(|_| "Não foi possível ler o arquivo de imagem.".to_string())?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = format!("{:x}", hasher.finalize());

    // Restringe a extensão a caracteres alfanuméricos: mesmo vindo do path escolhido pelo próprio
    // usuário no diálogo de arquivos, não deixamos nada além de [a-z0-9] entrar no nome final
    // gravado em `images_dir` (defesa em profundidade contra path traversal).
    let extension: String = source
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let extension = if extension.is_empty() { "png".to_string() } else { extension };
    let filename = format!("{hash}.{extension}");

    let dir = images_dir(&app)?;
    let target = dir.join(&filename);
    if !target.exists() {
        fs::write(&target, &bytes).map_err(|e| e.to_string())?;
    }

    let original_name = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("imagem")
        .to_string();

    Ok(ImportImageResult { filename, hash, original_name })
}

#[tauri::command]
pub fn delete_image_file(app: AppHandle, state: State<VaultState>, filename: String) -> Result<(), String> {
    require_unlocked(&state)?;
    let safe_name = sanitize_image_filename(&filename)?;
    let dir = images_dir(&app)?;
    let target = dir.join(safe_name);
    if target.exists() {
        fs::remove_file(&target).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn images_dir_path(app: AppHandle) -> Result<String, String> {
    Ok(images_dir(&app)?.to_string_lossy().to_string())
}

#[tauri::command]
pub fn list_images(app: AppHandle, state: State<VaultState>, query: Option<String>) -> Result<Vec<ImageRecord>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let trimmed = query.as_deref().map(str::trim).filter(|q| !q.is_empty());
    match trimmed {
        Some(q) => {
            let like = format!("%{q}%");
            let sql = format!("SELECT {IMAGE_COLUMNS} FROM images WHERE name LIKE ?1 OR original_name LIKE ?1 ORDER BY created_at DESC");
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let mapped = stmt.query_map(params![like], map_image).map_err(|e| e.to_string())?;
            mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
        }
        None => {
            let sql = format!("SELECT {IMAGE_COLUMNS} FROM images ORDER BY created_at DESC");
            let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
            let mapped = stmt.query_map([], map_image).map_err(|e| e.to_string())?;
            mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
        }
    }
}

#[tauri::command]
pub fn update_image_name(app: AppHandle, state: State<VaultState>, id: i64, name: String) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let name = validate::trim_optional(&name, NAME_MAX, "O nome da imagem")?;
    let conn = db::open(&app)?;
    conn.execute("UPDATE images SET name = ?1 WHERE id = ?2", params![name, id]).map_err(|e| e.to_string())?;
    Ok(())
}

fn count_where(conn: &rusqlite::Connection, sql: &str, image_id: i64) -> Result<i64, String> {
    conn.query_row(sql, [image_id], |row| row.get(0)).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn count_projects_using_image(app: AppHandle, state: State<VaultState>, image_id: i64) -> Result<i64, String> {
    require_unlocked(&state)?;
    validate::positive_id(image_id, "image_id")?;
    let conn = db::open(&app)?;
    count_where(&conn, "SELECT COUNT(*) FROM projects WHERE avatar_image_id = ?1", image_id)
}

#[tauri::command]
pub fn count_platforms_using_image(app: AppHandle, state: State<VaultState>, image_id: i64) -> Result<i64, String> {
    require_unlocked(&state)?;
    validate::positive_id(image_id, "image_id")?;
    let conn = db::open(&app)?;
    count_where(&conn, "SELECT COUNT(*) FROM platforms WHERE logo_image_id = ?1", image_id)
}

#[tauri::command]
pub fn count_accounts_using_image(app: AppHandle, state: State<VaultState>, image_id: i64) -> Result<i64, String> {
    require_unlocked(&state)?;
    validate::positive_id(image_id, "image_id")?;
    let conn = db::open(&app)?;
    count_where(&conn, "SELECT COUNT(*) FROM accounts WHERE avatar_image_id = ?1", image_id)
}

#[tauri::command]
pub fn get_image_by_id(app: AppHandle, state: State<VaultState>, id: i64) -> Result<Option<ImageRecord>, String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    let sql = format!("SELECT {IMAGE_COLUMNS} FROM images WHERE id = ?1");
    conn.query_row(&sql, [id], map_image).optional().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn find_image_by_hash(app: AppHandle, state: State<VaultState>, hash: String) -> Result<Option<ImageRecord>, String> {
    require_unlocked(&state)?;
    if !is_valid_sha256_hex(&hash) {
        return Ok(None);
    }
    let conn = db::open(&app)?;
    let sql = format!("SELECT {IMAGE_COLUMNS} FROM images WHERE hash = ?1");
    conn.query_row(&sql, [hash], map_image).optional().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn create_image_record(
    app: AppHandle,
    state: State<VaultState>,
    filename: String,
    original_name: String,
    hash: String,
) -> Result<ImageRecord, String> {
    require_unlocked(&state)?;
    let filename = sanitize_image_filename(&filename)?.to_string();
    if !is_valid_sha256_hex(&hash) {
        return Err("Hash de imagem inválido.".to_string());
    }
    let original_name = validate::trim_optional(&original_name, NAME_MAX, "O nome original")?;

    let conn = db::open(&app)?;
    let sql = format!("SELECT {IMAGE_COLUMNS} FROM images WHERE hash = ?1");
    if let Some(existing) = conn.query_row(&sql, [&hash], map_image).optional().map_err(|e| e.to_string())? {
        return Ok(existing);
    }

    conn.execute(
        "INSERT INTO images (filename, original_name, hash, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![filename, original_name, hash, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(ImageRecord {
        id: conn.last_insert_rowid(),
        filename,
        original_name,
        name: None,
        hash,
        created_at: db::now_iso(),
    })
}

#[tauri::command]
pub fn delete_image_record(app: AppHandle, state: State<VaultState>, id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(id, "id")?;
    let conn = db::open(&app)?;
    conn.execute("DELETE FROM images WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn clear_avatar_for_image(app: AppHandle, state: State<VaultState>, image_id: i64) -> Result<(), String> {
    require_unlocked(&state)?;
    validate::positive_id(image_id, "image_id")?;
    let conn = db::open(&app)?;
    conn.execute("UPDATE accounts SET avatar_image_id = NULL WHERE avatar_image_id = ?1", [image_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regressão de segurança (SECURITY_AUDIT.md): `delete_image_file` não pode escapar de
    // `images_dir` via path traversal.
    #[test]
    fn rejects_path_traversal_attempts() {
        assert!(sanitize_image_filename("../../secret.txt").is_err());
        assert!(sanitize_image_filename("..\\..\\secret.txt").is_err());
        assert!(sanitize_image_filename("..").is_err());
        assert!(sanitize_image_filename("C:\\Windows\\System32\\evil.dll").is_err());
        assert!(sanitize_image_filename("/etc/passwd").is_err());
        assert!(sanitize_image_filename("").is_err());
    }

    #[test]
    fn accepts_normal_generated_filenames() {
        assert!(sanitize_image_filename("a1b2c3d4e5f6.png").is_ok());
        assert!(sanitize_image_filename("photo.jpg").is_ok());
    }

    // Regressão de segurança (SECURITY_AUDIT_PHASE_3.md): `create_image_record` recebe o hash
    // vindo da WebView — precisa ter o formato de um sha256 real antes de ser gravado, para não
    // virar um "KV store" arbitrário de string->filename via a coluna `hash`.
    #[test]
    fn rejects_hashes_with_wrong_shape() {
        assert!(!is_valid_sha256_hex(""));
        assert!(!is_valid_sha256_hex("abc"));
        assert!(!is_valid_sha256_hex(&"a".repeat(63)));
        assert!(!is_valid_sha256_hex(&"g".repeat(64)));
        assert!(!is_valid_sha256_hex(&format!("{}{}", "a".repeat(64), "; DROP TABLE images;--")));
    }

    #[test]
    fn accepts_real_sha256_hex() {
        assert!(is_valid_sha256_hex(&"a".repeat(64)));
        assert!(is_valid_sha256_hex(&"0123456789abcdef".repeat(4)));
    }
}
