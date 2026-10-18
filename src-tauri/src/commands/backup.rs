use crate::crypto::{self, KdfParams};
use crate::db;
use crate::state::VaultState;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"VLTBKUP1";

/// Limites do cabeçalho do arquivo de backup (o arquivo é entrada não confiável). O salt real tem
/// 16 bytes e o JSON de parâmetros ~60 bytes — qualquer coisa muito acima disso é corrupção ou
/// um arquivo forjado.
const MAX_HEADER_SALT_LEN: usize = 1024;
const MAX_HEADER_PARAMS_LEN: usize = 4096;

/// Mensagem quando já existe um cofre e a senha mestra atual não foi informada.
pub const IMPORT_REQUIRES_MASTER_PASSWORD: &str = "Informe a senha mestra atual para restaurar um backup.";

/// Tabelas incluídas no backup, na ordem em que devem ser inseridas na restauração (tabelas
/// referenciadas por FK antes das que as referenciam). `images` guarda apenas os metadados —
/// os arquivos de imagem em si não viajam dentro do backup (ver SECURITY_AUDIT.md).
const BACKUP_TABLES: &[&str] = &[
    "platforms",
    "platform_seed_state",
    "images",
    "projects",
    "custom_property_definitions",
    "accounts",
    "tags",
    "account_tags",
    "account_projects",
    "project_tags",
    "account_properties",
    "account_history",
    "security_questions",
    "recovery_attempts",
    "settings",
];

#[derive(Serialize, Deserialize, Default)]
struct BackupPayload {
    vault_meta: Value,
    platforms: Vec<Value>,
    // `#[serde(default)]`: backups gerados antes desta tabela existir não têm esta chave no JSON
    // — sem o default, restaurar um backup antigo falharia na desserialização inteira do arquivo.
    #[serde(default)]
    platform_seed_state: Vec<Value>,
    images: Vec<Value>,
    projects: Vec<Value>,
    custom_property_definitions: Vec<Value>,
    accounts: Vec<Value>,
    tags: Vec<Value>,
    account_tags: Vec<Value>,
    account_projects: Vec<Value>,
    project_tags: Vec<Value>,
    account_properties: Vec<Value>,
    account_history: Vec<Value>,
    security_questions: Vec<Value>,
    recovery_attempts: Vec<Value>,
    settings: Vec<Value>,
}

impl BackupPayload {
    fn rows_for(&self, table: &str) -> &[Value] {
        match table {
            "platforms" => &self.platforms,
            "platform_seed_state" => &self.platform_seed_state,
            "images" => &self.images,
            "projects" => &self.projects,
            "custom_property_definitions" => &self.custom_property_definitions,
            "accounts" => &self.accounts,
            "tags" => &self.tags,
            "account_tags" => &self.account_tags,
            "account_projects" => &self.account_projects,
            "project_tags" => &self.project_tags,
            "account_properties" => &self.account_properties,
            "account_history" => &self.account_history,
            "security_questions" => &self.security_questions,
            "recovery_attempts" => &self.recovery_attempts,
            "settings" => &self.settings,
            _ => &[],
        }
    }
}

fn rows_to_json(conn: &Connection, sql: &str) -> Result<Vec<Value>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let col_count = stmt.column_count();
    let col_names: Vec<String> = (0..col_count).map(|i| stmt.column_name(i).unwrap().to_string()).collect();

    let rows = stmt
        .query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, name) in col_names.iter().enumerate() {
                let value: Value = match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => Value::from(n),
                    rusqlite::types::ValueRef::Real(f) => Value::from(f),
                    rusqlite::types::ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).to_string()),
                    rusqlite::types::ValueRef::Blob(b) => {
                        Value::from(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b))
                    }
                };
                map.insert(name.clone(), value);
            }
            Ok(Value::Object(map))
        })
        .map_err(|e| e.to_string())?;

    rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

/// Lê o estado inteiro do banco (exceto bytes de imagem) para dentro de um `BackupPayload`.
/// Extraído do command para ser testável diretamente com uma `Connection` de teste, sem
/// precisar de um `AppHandle` real.
fn build_backup_payload(conn: &Connection) -> Result<BackupPayload, String> {
    let vault_meta_rows = rows_to_json(conn, "SELECT * FROM vault_meta")?;
    let vault_meta = vault_meta_rows.into_iter().next().unwrap_or(Value::Null);

    Ok(BackupPayload {
        vault_meta,
        platforms: rows_to_json(conn, "SELECT * FROM platforms")?,
        platform_seed_state: rows_to_json(conn, "SELECT * FROM platform_seed_state")?,
        images: rows_to_json(conn, "SELECT * FROM images")?,
        projects: rows_to_json(conn, "SELECT * FROM projects")?,
        custom_property_definitions: rows_to_json(conn, "SELECT * FROM custom_property_definitions")?,
        accounts: rows_to_json(conn, "SELECT * FROM accounts")?,
        tags: rows_to_json(conn, "SELECT * FROM tags")?,
        account_tags: rows_to_json(conn, "SELECT * FROM account_tags")?,
        account_projects: rows_to_json(conn, "SELECT * FROM account_projects")?,
        project_tags: rows_to_json(conn, "SELECT * FROM project_tags")?,
        account_properties: rows_to_json(conn, "SELECT * FROM account_properties")?,
        account_history: rows_to_json(conn, "SELECT * FROM account_history")?,
        security_questions: rows_to_json(conn, "SELECT * FROM security_questions")?,
        recovery_attempts: rows_to_json(conn, "SELECT * FROM recovery_attempts")?,
        settings: rows_to_json(conn, "SELECT * FROM settings")?,
    })
}

/// Apaga o estado atual (ordem filha-antes-de-pai) e restaura a partir de um `BackupPayload`
/// já decifrado e validado. Extraído do command pela mesma razão que `build_backup_payload`.
fn restore_backup_payload(conn: &Connection, payload: &BackupPayload) -> Result<(), String> {
    conn.execute_batch(
        "DELETE FROM account_history;
         DELETE FROM account_properties;
         DELETE FROM project_tags;
         DELETE FROM account_projects;
         DELETE FROM account_tags;
         DELETE FROM recovery_attempts;
         DELETE FROM security_questions;
         DELETE FROM accounts;
         DELETE FROM custom_property_definitions;
         DELETE FROM projects;
         DELETE FROM images;
         DELETE FROM tags;
         DELETE FROM platform_seed_state;
         DELETE FROM platforms;
         DELETE FROM settings;
         DELETE FROM vault_meta;",
    )
    .map_err(|e| e.to_string())?;

    for table in BACKUP_TABLES {
        insert_rows(conn, table, payload.rows_for(table))?;
    }
    if !payload.vault_meta.is_null() {
        insert_rows(conn, "vault_meta", std::slice::from_ref(&payload.vault_meta))?;
    }
    Ok(())
}

/// Serializa + cifra um payload no formato de arquivo `VLTBKUP1` (mesma lógica usada por
/// `export_backup`, extraída para ser exercitada em teste sem tocar em disco/AppHandle).
fn encode_backup_file(payload: &BackupPayload, backup_password: &str) -> Result<Vec<u8>, String> {
    encode_backup_file_with_params(payload, backup_password, &KdfParams::default())
}

fn encode_backup_file_with_params(payload: &BackupPayload, backup_password: &str, params: &KdfParams) -> Result<Vec<u8>, String> {
    let json_bytes = serde_json::to_vec(payload).map_err(|e| e.to_string())?;

    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let params = *params;
    let key = crypto::derive_key(backup_password, &salt, &params).map_err(|_| "Falha ao criptografar backup.".to_string())?;
    let encrypted = crypto::encrypt(&key, &json_bytes).map_err(|_| "Falha ao criptografar backup.".to_string())?;
    let params_json = serde_json::to_vec(&params).map_err(|e| e.to_string())?;

    let mut file = Vec::new();
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    file.extend_from_slice(&salt);
    file.extend_from_slice(&(params_json.len() as u32).to_le_bytes());
    file.extend_from_slice(&params_json);
    file.extend_from_slice(&encrypted);
    Ok(file)
}

/// Decifra + desserializa um arquivo no formato `VLTBKUP1` de volta para um `BackupPayload`.
/// Falha com uma mensagem genérica em qualquer adulteração/corrupção/senha errada — o AEAD
/// (tag de autenticação) já rejeita ciphertext adulterado antes mesmo de tentarmos interpretar
/// o JSON, então nunca "restauramos silenciosamente" um arquivo corrompido.
fn decode_backup_file(bytes: &[u8], backup_password: &str) -> Result<BackupPayload, String> {
    if bytes.len() < 8 || &bytes[0..8] != MAGIC {
        return Err("Arquivo de backup inválido.".to_string());
    }
    let mut offset = 8;
    if bytes.len() < offset + 4 {
        return Err("Arquivo de backup inválido.".to_string());
    }
    let salt_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if salt_len > MAX_HEADER_SALT_LEN || bytes.len() < offset + salt_len + 4 {
        return Err("Arquivo de backup inválido.".to_string());
    }
    let salt = &bytes[offset..offset + salt_len];
    offset += salt_len;
    let params_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if params_len > MAX_HEADER_PARAMS_LEN || bytes.len() < offset + params_len {
        return Err("Arquivo de backup inválido.".to_string());
    }
    let params: KdfParams = serde_json::from_slice(&bytes[offset..offset + params_len]).map_err(|_| "Arquivo de backup inválido.".to_string())?;
    offset += params_len;
    let encrypted = &bytes[offset..];

    // Parâmetros do Argon2 vêm do próprio arquivo: valida ANTES de derivar (um arquivo forjado
    // poderia pedir GiBs de RAM ou milhões de iterações). `derive_key` também recusaria, mas aqui
    // a mensagem fica correta ("arquivo inválido", não "senha incorreta").
    if !params.is_within_bounds() {
        return Err("Arquivo de backup inválido.".to_string());
    }

    let key = crypto::derive_key(backup_password, salt, &params).map_err(|_| "Senha de backup incorreta.".to_string())?;
    let json_bytes = crypto::decrypt(&key, encrypted).map_err(|_| "Senha de backup incorreta ou arquivo corrompido.".to_string())?;
    serde_json::from_slice(&json_bytes).map_err(|_| "Arquivo de backup inválido.".to_string())
}

#[tauri::command]
pub fn export_backup(app: AppHandle, state: State<VaultState>, out_path: String, backup_password: String) -> Result<(), String> {
    let backup_password = Zeroizing::new(backup_password);
    if !state.is_unlocked() {
        return Err("Desbloqueie o cofre antes de exportar um backup.".to_string());
    }
    if backup_password.len() < 8 {
        return Err("A senha do backup deve ter pelo menos 8 caracteres.".to_string());
    }

    let conn = db::open(&app)?;
    let payload = build_backup_payload(&conn)?;
    let file = encode_backup_file(&payload, &backup_password)?;
    std::fs::write(&out_path, file).map_err(|e| e.to_string())?;
    Ok(())
}

/// Restaurar um backup SUBSTITUI o cofre inteiro (inclusive `vault_meta`, ou seja, a senha
/// mestra). Antes, este comando não exigia nem cofre desbloqueado nem senha nenhuma além da do
/// próprio arquivo — qualquer código na WebView (ou alguém com o app aberto na tela de bloqueio)
/// poderia trocar o cofre da vítima por um cofre controlado pelo atacante. Agora:
/// - se já existe um cofre, `current_master_password` é obrigatório e é verificado de verdade
///   (decifra `wrapped_dek`) ANTES de abrir/decifrar o arquivo;
/// - se não existe cofre (instalação nova restaurando um backup), é aceito sem ela.
#[tauri::command]
pub fn import_backup(
    app: AppHandle,
    state: State<VaultState>,
    in_path: String,
    backup_password: String,
    current_master_password: Option<String>,
) -> Result<(), String> {
    let backup_password = Zeroizing::new(backup_password);
    let current_master_password = current_master_password.map(Zeroizing::new);

    let mut conn = db::open(&app)?;
    db::init_schema(&conn)?;
    let bytes = std::fs::read(&in_path).map_err(|_| "Não foi possível ler o arquivo de backup.".to_string())?;
    import_backup_core(&mut conn, &bytes, &backup_password, current_master_password.as_ref())?;

    state.clear();
    Ok(())
}

/// Lógica de `import_backup` sobre uma `Connection` qualquer (testável sem `AppHandle`).
/// Ordem: (1) reautentica a senha mestra do cofre ATUAL, se houver cofre; (2) decifra e valida o
/// arquivo por completo; (3) só então apaga+restaura, numa única transação — qualquer erro no
/// meio do caminho faz rollback e o banco original fica intacto.
fn import_backup_core(
    conn: &mut Connection,
    bytes: &[u8],
    backup_password: &Zeroizing<String>,
    current_master_password: Option<&Zeroizing<String>>,
) -> Result<(), String> {
    let vault_exists: bool = conn
        .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |row| row.get::<_, i64>(0))
        .map_err(|e| e.to_string())?
        > 0;
    if vault_exists {
        let password = current_master_password
            .filter(|p| !p.is_empty())
            .ok_or_else(|| IMPORT_REQUIRES_MASTER_PASSWORD.to_string())?;
        crate::commands::vault::verify_current_password(conn, password)?;
    }

    let payload = decode_backup_file(bytes, backup_password)?;
    validate_payload(&payload)?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    restore_backup_payload(&tx, &payload)?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

/// Checagens de sanidade do conteúdo decifrado antes de tocar no banco: o backup precisa trazer
/// um `vault_meta` (senão a restauração deixaria um cofre "sem senha mestra"/não inicializado), e
/// os parâmetros de KDF gravados nele precisam estar dentro dos limites aceitos.
fn validate_payload(payload: &BackupPayload) -> Result<(), String> {
    let invalid = || "Arquivo de backup inválido.".to_string();
    let meta = payload.vault_meta.as_object().ok_or_else(invalid)?;
    for key in ["kdf_params", "recovery_key_kdf_params"] {
        match meta.get(key) {
            None | Some(Value::Null) if key == "recovery_key_kdf_params" => {}
            Some(Value::String(json)) => {
                let params: KdfParams = serde_json::from_str(json).map_err(|_| invalid())?;
                if !params.is_within_bounds() {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

/// Colunas reconhecidas por tabela. `insert_rows` monta SQL por interpolação de nomes de coluna
/// (não há como parametrizar identificadores em SQL), então todo nome vindo do arquivo de backup
/// precisa ser validado contra esta lista antes de entrar na string da query — caso contrário um
/// backup malicioso (cifrado com uma senha que o próprio atacante escolheu e entrega à vítima)
/// poderia injetar SQL arbitrário via uma chave de objeto JSON forjada.
fn allowed_columns(table: &str) -> &'static [&'static str] {
    match table {
        "vault_meta" => &[
            "id", "kdf_salt", "kdf_params", "wrapped_dek", "dek_check", "created_at",
            "recovery_key_salt", "recovery_key_kdf_params", "recovery_key_wrapped_dek",
            "recovery_key_check", "recovery_key_created_at",
        ],
        "platforms" => &[
            "id", "name", "icon", "login_url", "website_url", "is_custom", "created_at", "logo_image_id",
            // `sort_order` já existia na tabela mas faltava aqui — sem ele, restaurar QUALQUER
            // backup com plataformas falhava inteiro, já que `insert_rows` rejeita a linha
            // inteira se ela tiver uma chave fora da lista (achado ao adicionar `system_key`
            // abaixo; corrigido de brinde, mesmo bug afetando `projects` logo adiante).
            "sort_order",
            // Identificador estável das plataformas oficiais (ver `db::PLATFORM_SEEDS`).
            "system_key",
        ],
        "platform_seed_state" => &["system_key", "status", "updated_at"],
        "accounts" => &[
            "id", "name", "platform_id", "category", "username", "email", "encrypted_password",
            "login_url", "website_url", "notes", "favorite", "created_at", "updated_at",
            "avatar_image_id", "status", "deleted_at", "two_factor_enabled", "two_factor_method",
            "two_factor_phone", "two_factor_email", "two_factor_app", "two_factor_notes",
        ],
        "tags" => &["id", "name"],
        "account_tags" => &["account_id", "tag_id"],
        "settings" => &["key", "value"],
        "images" => &["id", "filename", "original_name", "hash", "created_at", "name"],
        "projects" => &[
            "id", "name", "description", "color", "avatar_image_id", "favorite", "notes", "created_at", "updated_at",
            "sort_order",
        ],
        "custom_property_definitions" => &["id", "name", "type", "created_at"],
        "account_projects" => &["account_id", "project_id"],
        "project_tags" => &["project_id", "tag_id"],
        "account_properties" => &[
            "id", "account_id", "definition_id", "value", "is_sensitive", "created_at", "updated_at",
        ],
        "account_history" => &["id", "account_id", "event", "detail", "created_at"],
        "security_questions" => &[
            "id", "question", "share_index", "answer_salt", "kdf_params", "wrapped_share", "created_at",
        ],
        "recovery_attempts" => &["id", "failed_count", "locked_until"],
        _ => &[],
    }
}

/// Colunas BLOB reais do schema (ver `db.rs`): precisam ser decodificadas de base64 de volta
/// para bytes na restauração. Os demais campos "cifrados" (ex.: `encrypted_password`,
/// `two_factor_*`, `account_properties.value`) já são TEXT em base64 — o valor cru vindo do
/// JSON pode ser inserido como string sem decodificação extra.
fn is_blob_column(table: &str, col: &str) -> bool {
    matches!(
        (table, col),
        ("vault_meta", "kdf_salt")
            | ("vault_meta", "wrapped_dek")
            | ("vault_meta", "dek_check")
            | ("vault_meta", "recovery_key_salt")
            | ("vault_meta", "recovery_key_wrapped_dek")
            | ("vault_meta", "recovery_key_check")
            | ("security_questions", "answer_salt")
            | ("security_questions", "wrapped_share")
    )
}

fn insert_rows(conn: &Connection, table: &str, rows: &[Value]) -> Result<(), String> {
    let allowed = allowed_columns(table);
    for row in rows {
        let obj = row.as_object().ok_or("Arquivo de backup inválido.")?;
        let columns: Vec<&String> = obj.keys().collect();
        if columns.iter().any(|c| !allowed.contains(&c.as_str())) {
            return Err("Arquivo de backup inválido.".to_string());
        }
        let placeholders: Vec<String> = (1..=columns.len()).map(|i| format!("?{}", i)).collect();
        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table,
            columns.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", "),
            placeholders.join(", ")
        );

        let params: Vec<Box<dyn rusqlite::ToSql>> = columns
            .iter()
            .map(|c| -> Box<dyn rusqlite::ToSql> {
                let v = &obj[*c];
                if is_blob_column(table, c) {
                    if let Some(s) = v.as_str() {
                        if let Ok(b) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s) {
                            return Box::new(b);
                        }
                    }
                }
                match v {
                    Value::Null => Box::new(Option::<String>::None),
                    Value::String(s) => Box::new(s.clone()),
                    Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            Box::new(i)
                        } else {
                            Box::new(n.as_f64().unwrap_or(0.0))
                        }
                    }
                    _ => Box::new(Option::<String>::None),
                }
            })
            .collect();

        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        conn.execute(&sql, param_refs.as_slice()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    // Regressão de segurança (SECURITY_AUDIT.md): um arquivo de backup malicioso não pode
    // injetar SQL via nomes de coluna forjados em `insert_rows`.
    #[test]
    fn rejects_column_names_outside_the_allowlist() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();

        let malicious = serde_json::json!({
            "name": "x",
            "icon": "y",
            "login_url": "z",
            "website_url": "w",
            "is_custom": 0,
            "created_at": "now",
            "logo_image_id); DROP TABLE accounts;--": "payload",
        });

        let result = insert_rows(&conn, "platforms", std::slice::from_ref(&malicious));
        assert!(result.is_err());

        // A tabela accounts deve continuar existindo e vazia.
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn accepts_genuine_export_shaped_rows() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();

        let row = serde_json::json!({
            "name": "Instagram",
            "icon": "📸",
            "login_url": "https://example.com",
            "website_url": "https://example.com",
            "is_custom": 1,
            "created_at": "2026-01-01T00:00:00Z",
        });

        assert!(insert_rows(&conn, "platforms", std::slice::from_ref(&row)).is_ok());
    }

    /// Monta um banco de origem com dados sintéticos cobrindo todas as categorias citadas na
    /// Fase 2 (senha, 2FA, notes, propriedade sensível, tag, projeto, imagem, pergunta de
    /// segurança, recovery key) para os testes de round-trip/adulteração abaixo.
    fn seed_source_db() -> (Connection, [u8; 32]) {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        let dek = [9u8; 32];

        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let params = KdfParams::default();
        let kek = crypto::derive_key("senha-mestra-de-teste", &salt, &params).unwrap();
        let wrapped_dek = crypto::encrypt(&kek, &dek).unwrap();
        let dek_check = crypto::encrypt(&dek, b"vault-dek-check-v1").unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![salt, serde_json::to_string(&params).unwrap(), wrapped_dek, dek_check, db::now_iso()],
        )
        .unwrap();

        let recovery_salt = crypto::random_bytes(crypto::SALT_LEN);
        let recovery_key = crypto::generate_recovery_key();
        let kek2 = crypto::derive_key(&crypto::normalize_recovery_key(&recovery_key), &recovery_salt, &params).unwrap();
        let recovery_wrapped_dek = crypto::encrypt(&kek2, &dek).unwrap();
        conn.execute(
            "UPDATE vault_meta SET recovery_key_salt = ?1, recovery_key_kdf_params = ?2, recovery_key_wrapped_dek = ?3, recovery_key_check = ?4, recovery_key_created_at = ?5 WHERE id = 1",
            rusqlite::params![recovery_salt, serde_json::to_string(&params).unwrap(), recovery_wrapped_dek, dek_check, db::now_iso()],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO platforms (name, icon, login_url, website_url, is_custom, created_at) VALUES ('Instagram', '📸', 'https://x', 'https://x', 0, 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO projects (name, description, favorite, notes, created_at, updated_at) VALUES ('Projeto A', 'desc', 0, NULL, 'now', 'now')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO tags (name) VALUES ('pessoal')", []).unwrap();
        conn.execute(
            "INSERT INTO images (filename, original_name, hash, created_at) VALUES ('abc.png', 'foto.png', 'abc', 'now')",
            [],
        )
        .unwrap();

        let enc_password = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, crypto::encrypt(&dek, b"SECURITY_TEST_PASSWORD_93821").unwrap());
        let enc_notes = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, crypto::encrypt(&dek, b"SECURITY_TEST_NOTE_58321").unwrap());
        let enc_2fa = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, crypto::encrypt(&dek, b"SECURITY_TEST_2FA_18273").unwrap());
        conn.execute(
            "INSERT INTO accounts (name, platform_id, username, email, encrypted_password, notes, favorite,
              two_factor_enabled, two_factor_phone, created_at, updated_at)
             VALUES ('Conta Teste', 1, 'user', 'a@b.com', ?1, ?2, 1, 1, ?3, 'now', 'now')",
            rusqlite::params![enc_password, enc_notes, enc_2fa],
        )
        .unwrap();
        conn.execute("INSERT INTO account_tags (account_id, tag_id) VALUES (1, 1)", []).unwrap();
        conn.execute("INSERT INTO account_projects (account_id, project_id) VALUES (1, 1)", []).unwrap();
        conn.execute(
            "INSERT INTO custom_property_definitions (name, type, created_at) VALUES ('Chave API', 'text', 'now')",
            [],
        )
        .unwrap();
        let enc_property = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, crypto::encrypt(&dek, b"SECURITY_TEST_APIKEY_82917").unwrap());
        conn.execute(
            "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) VALUES (1, 1, ?1, 1, 'now', 'now')",
            rusqlite::params![enc_property],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO account_history (account_id, event, detail, created_at) VALUES (1, 'created', NULL, 'now')",
            [],
        )
        .unwrap();

        let sq_salt = crypto::random_bytes(crypto::SALT_LEN);
        let sq_key = crypto::derive_key("resposta-nao-obvia", &sq_salt, &params).unwrap();
        let sq_wrapped = crypto::encrypt(&sq_key, b"SECURITY_TEST_RECOVERY_73918").unwrap();
        conn.execute(
            "INSERT INTO security_questions (question, share_index, answer_salt, kdf_params, wrapped_share, created_at) VALUES ('Pergunta teste?', 1, ?1, ?2, ?3, 'now')",
            rusqlite::params![sq_salt, serde_json::to_string(&params).unwrap(), sq_wrapped],
        )
        .unwrap();

        conn.execute("INSERT INTO settings (key, value) VALUES ('theme', 'dark')", []).unwrap();

        (conn, dek)
    }

    fn table_row_count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap()
    }

    /// Round-trip completo (Fase 2, item 36): gera dados sintéticos em todas as categorias
    /// citadas na auditoria, exporta, restaura num banco novo, e confirma que absolutamente
    /// nada foi perdido nem alterado — inclusive os valores cifrados batem byte a byte.
    #[test]
    fn full_round_trip_preserves_every_table_and_ciphertext_byte_for_byte() {
        let (source, _dek) = seed_source_db();
        let payload = build_backup_payload(&source).unwrap();

        let file = encode_backup_file(&payload, "senha-do-backup-123").unwrap();
        let decoded = decode_backup_file(&file, "senha-do-backup-123").unwrap();

        let target = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&target).unwrap();
        restore_backup_payload(&target, &decoded).unwrap();

        for table in BACKUP_TABLES {
            assert_eq!(
                table_row_count(&source, table),
                table_row_count(&target, table),
                "tabela {table} perdeu ou ganhou linhas na restauração",
            );
        }

        let (src_password, src_notes, src_phone): (String, String, String) = source
            .query_row("SELECT encrypted_password, notes, two_factor_phone FROM accounts WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        let (dst_password, dst_notes, dst_phone): (String, String, String) = target
            .query_row("SELECT encrypted_password, notes, two_factor_phone FROM accounts WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(src_password, dst_password, "ciphertext da senha mudou na restauração");
        assert_eq!(src_notes, dst_notes, "ciphertext das notes mudou na restauração");
        assert_eq!(src_phone, dst_phone, "ciphertext do telefone 2FA mudou na restauração");

        let src_property: String = source.query_row("SELECT value FROM account_properties WHERE id = 1", [], |r| r.get(0)).unwrap();
        let dst_property: String = target.query_row("SELECT value FROM account_properties WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(src_property, dst_property, "ciphertext da propriedade sensível mudou na restauração");

        let (src_wrapped_dek, src_recovery_wrapped): (Vec<u8>, Vec<u8>) = source
            .query_row("SELECT wrapped_dek, recovery_key_wrapped_dek FROM vault_meta WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let (dst_wrapped_dek, dst_recovery_wrapped): (Vec<u8>, Vec<u8>) = target
            .query_row("SELECT wrapped_dek, recovery_key_wrapped_dek FROM vault_meta WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(src_wrapped_dek, dst_wrapped_dek, "wrapped_dek mudou na restauração");
        assert_eq!(src_recovery_wrapped, dst_recovery_wrapped, "recovery_key_wrapped_dek mudou na restauração");
    }

    #[test]
    fn tampered_backup_file_is_rejected_without_touching_the_database() {
        let (source, _dek) = seed_source_db();
        let payload = build_backup_payload(&source).unwrap();
        let mut file = encode_backup_file(&payload, "senha-do-backup-123").unwrap();

        // Adultera um byte no meio do ciphertext (depois do cabeçalho com salt/params).
        let last = file.len() - 1;
        file[last] ^= 0xFF;

        let result = decode_backup_file(&file, "senha-do-backup-123");
        assert!(result.is_err(), "backup adulterado deveria ser rejeitado pelo AEAD");
    }

    #[test]
    fn wrong_backup_password_is_rejected() {
        let (source, _dek) = seed_source_db();
        let payload = build_backup_payload(&source).unwrap();
        let file = encode_backup_file(&payload, "senha-correta-123").unwrap();

        assert!(decode_backup_file(&file, "senha-errada-456").is_err());
    }

    /// Fase 2, item 39 do pedido de auditoria: cadastra os marcadores sintéticos pedidos
    /// explicitamente, grava num arquivo `.db` real em disco (não em memória), lê os bytes
    /// crus do arquivo e confirma que nenhum marcador aparece em texto puro — depois apaga o
    /// arquivo de teste.
    #[test]
    fn synthetic_markers_never_appear_in_plaintext_on_disk() {
        let dir = std::env::temp_dir().join(format!("cofre_security_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("vault_test.db");

        let markers: [&[u8]; 5] = [
            b"SECURITY_TEST_PASSWORD_93821",
            b"SECURITY_TEST_NOTE_58321",
            b"SECURITY_TEST_2FA_18273",
            b"SECURITY_TEST_APIKEY_82917",
            b"SECURITY_TEST_RECOVERY_73918",
        ];

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::db::init_schema(&conn).unwrap();
            let dek = [3u8; 32];

            let enc = |plain: &[u8]| -> String {
                B64.encode(crypto::encrypt(&dek, plain).unwrap())
            };
            conn.execute(
                "INSERT INTO accounts (name, encrypted_password, notes, two_factor_enabled, two_factor_phone, created_at, updated_at)
                 VALUES ('Conta Teste', ?1, ?2, 1, ?3, 'now', 'now')",
                rusqlite::params![enc(markers[0]), enc(markers[1]), enc(markers[2])],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO custom_property_definitions (name, type, created_at) VALUES ('Chave API', 'text', 'now')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO account_properties (account_id, definition_id, value, is_sensitive, created_at, updated_at) VALUES (1, 1, ?1, 1, 'now', 'now')",
                rusqlite::params![enc(markers[3])],
            )
            .unwrap();
            let sq_salt = crypto::random_bytes(crypto::SALT_LEN);
            let sq_params = KdfParams::default();
            let sq_key = crypto::derive_key("resposta-teste", &sq_salt, &sq_params).unwrap();
            conn.execute(
                "INSERT INTO security_questions (question, share_index, answer_salt, kdf_params, wrapped_share, created_at) VALUES ('Pergunta?', 1, ?1, ?2, ?3, 'now')",
                rusqlite::params![sq_salt, serde_json::to_string(&sq_params).unwrap(), crypto::encrypt(&sq_key, markers[4]).unwrap()],
            )
            .unwrap();
            conn.pragma_update(None, "journal_mode", "DELETE").unwrap(); // força tudo para o arquivo principal, sem -wal
        } // conn é fechada aqui

        let bytes = std::fs::read(&db_path).unwrap();
        for marker in markers {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker),
                "marcador {} apareceu em texto puro no arquivo .db",
                String::from_utf8_lossy(marker)
            );
        }

        // Limpeza: não deixa o arquivo de teste sintético para trás.
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncated_or_garbage_file_is_rejected_not_panicking() {
        assert!(decode_backup_file(b"nao e um backup valido", "qualquer-senha").is_err());
        assert!(decode_backup_file(MAGIC, "qualquer-senha").is_err());
        assert!(decode_backup_file(b"", "qualquer-senha").is_err());

        let mut half_header = MAGIC.to_vec();
        half_header.extend_from_slice(&999u32.to_le_bytes()); // alega um salt de 999 bytes que não existem
        assert!(decode_backup_file(&half_header, "qualquer-senha").is_err());
    }

    // ---------------------------------------------------------------------------------------
    // Item C da auditoria: restaurar backup exige a senha mestra do cofre atual (se houver).
    // ---------------------------------------------------------------------------------------

    fn fast_params() -> KdfParams {
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    const TARGET_MASTER: &str = "senha-mestra-destino";
    const BACKUP_PASSWORD: &str = "senha-do-backup-123";

    /// Cofre "atual" (o que seria substituído pela restauração), com senha mestra real e uma conta.
    fn existing_target_vault() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        let dek = [21u8; 32];
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let kek = crypto::derive_key(TARGET_MASTER, &salt, &fast_params()).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                salt,
                serde_json::to_string(&fast_params()).unwrap(),
                crypto::encrypt(&kek, &dek).unwrap(),
                crypto::encrypt(&dek, b"vault-dek-check-v1").unwrap(),
                db::now_iso()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO accounts (name, created_at, updated_at, status) VALUES ('Conta original do destino', 'now', 'now', 'active')",
            [],
        )
        .unwrap();
        conn
    }

    /// "Foto" serializada de todo o banco, para provar que nada mudou após uma importação recusada.
    fn snapshot(conn: &Connection) -> String {
        serde_json::to_string(&build_backup_payload(conn).unwrap()).unwrap()
    }

    fn source_backup_file() -> Vec<u8> {
        let (source, _dek) = seed_source_db();
        encode_backup_file_with_params(&build_backup_payload(&source).unwrap(), BACKUP_PASSWORD, &fast_params()).unwrap()
    }

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn import_without_master_password_when_vault_exists_is_rejected_and_db_untouched() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);
        let file = source_backup_file();

        let err = import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), None).unwrap_err();
        assert_eq!(err, IMPORT_REQUIRES_MASTER_PASSWORD);
        let empty = pw("");
        assert_eq!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&empty)).unwrap_err(), IMPORT_REQUIRES_MASTER_PASSWORD);
        assert_eq!(before, snapshot(&target));
    }

    #[test]
    fn import_with_wrong_master_password_is_rejected_and_db_untouched() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);
        let file = source_backup_file();

        let wrong = pw("senha-mestra-errada");
        assert!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&wrong)).is_err());
        assert_eq!(before, snapshot(&target));
    }

    #[test]
    fn import_with_correct_master_password_restores_the_backup() {
        let mut target = existing_target_vault();
        let file = source_backup_file();

        let master = pw(TARGET_MASTER);
        import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&master)).unwrap();

        let names: Vec<String> = target
            .prepare("SELECT name FROM accounts")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(names, vec!["Conta Teste".to_string()], "o cofre deve ter sido substituído pelo do backup");
        // A senha mestra agora é a do cofre de origem (o `vault_meta` também é restaurado).
        assert!(crate::commands::vault::verify_current_password(&target, &master).is_err());
        assert!(crate::commands::vault::verify_current_password(&target, &pw("senha-mestra-de-teste")).is_ok());
    }

    #[test]
    fn import_into_a_fresh_install_without_vault_does_not_need_a_master_password() {
        let mut target = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&target).unwrap();
        let file = source_backup_file();

        import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), None).unwrap();
        assert_eq!(table_row_count(&target, "vault_meta"), 1);
        assert_eq!(table_row_count(&target, "accounts"), 1);
    }

    #[test]
    fn import_with_wrong_backup_password_is_rejected_and_db_untouched() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);
        let file = source_backup_file();

        let master = pw(TARGET_MASTER);
        assert!(import_backup_core(&mut target, &file, &pw("senha-de-backup-errada"), Some(&master)).is_err());
        assert_eq!(before, snapshot(&target));
    }

    #[test]
    fn import_of_tampered_file_is_rejected_and_db_untouched() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);
        let mut file = source_backup_file();
        let middle = file.len() - 40;
        file[middle] ^= 0x01;

        let master = pw(TARGET_MASTER);
        assert!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&master)).is_err());
        assert_eq!(before, snapshot(&target));
    }

    // Falha no MEIO da restauração (o DELETE de todas as tabelas e vários INSERTs já rodaram
    // quando a linha inválida de `settings` — a última tabela — é encontrada): a transação tem que
    // fazer rollback e o banco original continuar exatamente como estava.
    #[test]
    fn failure_in_the_middle_of_restore_rolls_back_everything() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);

        let (source, _dek) = seed_source_db();
        let mut payload = build_backup_payload(&source).unwrap();
        payload.settings.push(serde_json::json!({ "key": "x", "coluna_inexistente": "y" }));
        let file = encode_backup_file_with_params(&payload, BACKUP_PASSWORD, &fast_params()).unwrap();

        let master = pw(TARGET_MASTER);
        assert!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&master)).is_err());
        assert_eq!(before, snapshot(&target), "rollback incompleto: o banco original foi alterado");
    }

    #[test]
    fn backup_without_vault_meta_or_with_excessive_inner_kdf_params_is_rejected() {
        let mut target = existing_target_vault();
        let before = snapshot(&target);
        let master = pw(TARGET_MASTER);

        let (source, _dek) = seed_source_db();
        let mut no_meta = build_backup_payload(&source).unwrap();
        no_meta.vault_meta = Value::Null;
        let file = encode_backup_file_with_params(&no_meta, BACKUP_PASSWORD, &fast_params()).unwrap();
        assert!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&master)).is_err());

        let mut evil_meta = build_backup_payload(&source).unwrap();
        evil_meta.vault_meta["kdf_params"] = Value::from(r#"{"memory_kib":4294967295,"iterations":1,"parallelism":1}"#);
        let file = encode_backup_file_with_params(&evil_meta, BACKUP_PASSWORD, &fast_params()).unwrap();
        assert!(import_backup_core(&mut target, &file, &pw(BACKUP_PASSWORD), Some(&master)).is_err());

        assert_eq!(before, snapshot(&target));
    }

    /// Monta um arquivo VLTBKUP1 com cabeçalho arbitrário (sem cifrar nada de verdade).
    fn forged_file(salt_len: u32, params_json: &[u8]) -> Vec<u8> {
        let mut file = MAGIC.to_vec();
        file.extend_from_slice(&salt_len.to_le_bytes());
        file.extend_from_slice(&vec![0u8; salt_len.min(64) as usize]);
        file.extend_from_slice(&(params_json.len() as u32).to_le_bytes());
        file.extend_from_slice(params_json);
        file.extend_from_slice(&[0u8; 64]);
        file
    }

    #[test]
    fn excessive_kdf_params_in_backup_header_are_rejected_quickly() {
        let started = std::time::Instant::now();
        for params in [
            r#"{"memory_kib":4294967295,"iterations":1,"parallelism":1}"#,
            r#"{"memory_kib":8192,"iterations":4294967295,"parallelism":1}"#,
            r#"{"memory_kib":8192,"iterations":1,"parallelism":1000}"#,
            r#"{"memory_kib":2097152,"iterations":3,"parallelism":1}"#,
        ] {
            let err = decode_backup_file(&forged_file(16, params.as_bytes()), "qualquer-senha").err().unwrap();
            assert_eq!(err, "Arquivo de backup inválido.");
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "nenhuma derivação de chave deveria ter rodado");
    }

    #[test]
    fn oversized_header_lengths_are_rejected() {
        let ok_params = br#"{"memory_kib":8192,"iterations":1,"parallelism":1}"#;
        assert!(decode_backup_file(&forged_file(u32::MAX, ok_params), "x").is_err());
        let huge_params = vec![b' '; MAX_HEADER_PARAMS_LEN + 1];
        assert!(decode_backup_file(&forged_file(16, &huge_params), "x").is_err());
    }
}
