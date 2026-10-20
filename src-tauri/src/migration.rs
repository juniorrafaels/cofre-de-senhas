use crate::crypto;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rusqlite::Connection;

/// Colunas de `accounts` que devem sempre conter `base64(nonce || ciphertext+tag)` cifrado com
/// a DEK — nunca texto puro. Notes passou a entrar nesta lista na Fase 2 do hardening
/// (SECURITY_AUDIT_PHASE_2.md); os campos de 2FA já estavam aqui desde a Fase 1.
const ENCRYPTED_ACCOUNT_COLUMNS: &[&str] =
    &["notes", "two_factor_phone", "two_factor_email", "two_factor_app", "two_factor_notes"];

/// Um valor "parece cifrado" quando decodifica como base64 E o AEAD confirma a tag de
/// autenticação sob a DEK atual. Qualquer outra coisa (texto puro legado de antes da Fase 2,
/// ou lixo) falha uma das duas checagens — a chance de um texto arbitrário passar as duas por
/// acaso é a mesma de forjar uma tag Poly1305 de 128 bits, ou seja, desprezível.
fn looks_encrypted(dek: &[u8; 32], value: &str) -> bool {
    match B64.decode(value) {
        Ok(bytes) => crypto::decrypt(dek, &bytes).is_ok(),
        Err(_) => false,
    }
}

/// Migração automática e idempotente, executada a cada desbloqueio bem-sucedido (senha mestra,
/// perguntas de segurança ou recovery key — qualquer caminho que produza a DEK). Detecta campos
/// de `accounts` que ainda estão em texto puro (dados legados de antes de uma correção de
/// segurança) e os re-cifra in-place. Depois da primeira execução em cada linha, toda chamada
/// seguinte é uma checagem barata (`looks_encrypted` decifra em microssegundos, não usa Argon2)
/// que não faz nenhuma escrita — por isso é seguro rodar isso sempre, sem guardar um "já migrei"
/// em `settings`.
///
/// Retorna quantos campos (não linhas) foram migrados nesta chamada, só para fins de log local
/// (nunca loga o conteúdo em si).
pub fn migrate_plaintext_account_fields(conn: &Connection, dek: &[u8; 32]) -> Result<usize, String> {
    let select_cols = ENCRYPTED_ACCOUNT_COLUMNS.join(", ");
    let sql = format!("SELECT id, {select_cols} FROM accounts");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;

    let rows: Vec<(i64, Vec<Option<String>>)> = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let values = (0..ENCRYPTED_ACCOUNT_COLUMNS.len())
                .map(|i| row.get::<_, Option<String>>(i + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((id, values))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    drop(stmt);

    let mut migrated = 0usize;
    for (id, values) in rows {
        for (col, value) in ENCRYPTED_ACCOUNT_COLUMNS.iter().zip(values.into_iter()) {
            let Some(plain_or_cipher) = value else { continue };
            if plain_or_cipher.is_empty() || looks_encrypted(dek, &plain_or_cipher) {
                continue;
            }
            let ciphertext = crypto::encrypt(dek, plain_or_cipher.as_bytes())
                .map_err(|_| "Falha ao migrar dado sensível existente.".to_string())?;
            let encoded = B64.encode(ciphertext);
            conn.execute(&format!("UPDATE accounts SET {col} = ?1 WHERE id = ?2"), rusqlite::params![encoded, id])
                .map_err(|e| e.to_string())?;
            migrated += 1;
        }
    }
    Ok(migrated)
}

// ---------------------------------------------------------------------------------------------
// Metadados de conta/histórico → formato `enc:v2:` (fase 1 da criptografia de metadados)
// ---------------------------------------------------------------------------------------------

/// Colunas migradas: (tabela, coluna). Etiquetas, projetos e plataformas ficam FORA desta fase.
pub const METADATA_COLUMNS: &[(&str, &str)] = &[
    ("accounts", "name"),
    ("accounts", "category"),
    ("accounts", "username"),
    ("accounts", "email"),
    ("accounts", "login_url"),
    ("accounts", "website_url"),
    ("accounts", "last_login_at"),
    ("account_history", "detail"),
];

const PREMIGRATION_AAD: &[u8] = b"cofre/premigration-backup/v1";
const PREMIGRATION_SUFFIX: &str = ".pre-v2.bak";

/// Resultado de uma execução (só contagens — nunca valores).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MetadataMigrationReport {
    /// Valores legados em texto puro que viraram `enc:v2:` nesta execução.
    pub migrated: usize,
    /// Valores que já estavam em `enc:v2:` e autenticaram (não são cifrados de novo).
    pub already_v2: usize,
    /// `enc:v2:` que NÃO autentica (adulterado, copiado de outro campo, base64 inválido): deixado como está.
    pub corrupt: usize,
    /// Prefixo `enc:vN:` com N desconhecido (cofre de versão mais nova): deixado como está.
    pub unsupported_version: usize,
    /// Caminho do backup cifrado criado antes de escrever, se houve algo a migrar e o banco é um arquivo.
    pub backup_path: Option<std::path::PathBuf>,
}

struct PendingValue {
    table: &'static str,
    column: &'static str,
    id: i64,
    plaintext: String,
}

fn db_file_path(conn: &Connection) -> Option<std::path::PathBuf> {
    conn.path().filter(|p| !p.is_empty()).map(std::path::PathBuf::from)
}

/// Executa todas as migrações automáticas de desbloqueio. A migração de segredos legados
/// mantém o comportamento de sempre (erro = desbloqueio falha). A de metadados NUNCA impede o
/// desbloqueio: cofres antigos continuam abrindo (a leitura aceita texto legado), a transação
/// faz rollback sozinha e o diagnóstico seguro (só contagens/erro técnico, sem valores) vai para
/// o log local; ela tenta de novo no próximo desbloqueio.
pub fn migrate_all(conn: &Connection, dek: &[u8; 32]) -> Result<(), String> {
    migrate_plaintext_account_fields(conn, dek)?;
    match migrate_metadata_v2(conn, dek) {
        Ok(report) => {
            if report.migrated > 0 || report.corrupt > 0 || report.unsupported_version > 0 {
                eprintln!(
                    "[migration] metadados v2: migrados={} já_v2={} corrompidos={} versão_desconhecida={}",
                    report.migrated, report.already_v2, report.corrupt, report.unsupported_version
                );
            }
        }
        Err(e) => eprintln!("[migration] migração de metadados v2 não concluída (nada foi alterado): {e}"),
    }
    Ok(())
}

pub fn migrate_metadata_v2(conn: &Connection, dek: &[u8; 32]) -> Result<MetadataMigrationReport, String> {
    migrate_metadata_v2_with_hook(conn, dek, &mut |_| Ok(()))
}

/// `hook(i)` roda ANTES de cada linha ser reescrita (i = índice 0-based); se devolver erro, a
/// migração inteira sofre rollback. Em produção o hook é vazio; os testes o usam para simular
/// uma falha no meio.
pub(crate) fn migrate_metadata_v2_with_hook(
    conn: &Connection,
    dek: &[u8; 32],
    hook: &mut dyn FnMut(usize) -> Result<(), String>,
) -> Result<MetadataMigrationReport, String> {
    let mut report = MetadataMigrationReport::default();
    let mut pending: Vec<PendingValue> = Vec::new();

    for &(table, column) in METADATA_COLUMNS {
        let mut stmt = conn
            .prepare(&format!("SELECT id, {column} FROM {table} WHERE {column} IS NOT NULL"))
            .map_err(|e| e.to_string())?;
        let rows: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        for (id, value) in rows {
            if value.is_empty() {
                continue;
            }
            match crypto::decrypt_field(dek, table, column, id, &value) {
                Ok(plaintext) if value.starts_with(crypto::FIELD_PREFIX_V2) => {
                    let _ = plaintext;
                    report.already_v2 += 1;
                }
                Ok(plaintext) => pending.push(PendingValue { table, column, id, plaintext }),
                Err(crypto::FieldError::UnknownVersion) => report.unsupported_version += 1,
                Err(crypto::FieldError::Corrupt) => report.corrupt += 1,
            }
        }
    }

    if pending.is_empty() {
        return Ok(report);
    }

    // 1. Backup recuperável ANTES de escrever (só quando o banco é um arquivo).
    if let Some(path) = db_file_path(conn) {
        report.backup_path = Some(create_premigration_backup(conn, &path, dek)?);
    }

    // 2. `secure_delete` faz o SQLite zerar o conteúdo antigo ao reescrever/liberar células —
    // reduz (não elimina) vestígios do texto puro nas páginas do arquivo principal e do WAL.
    let _ = conn.pragma_update(None, "secure_delete", "ON");

    // 3. Tudo numa transação: qualquer falha (inclusive a verificação de leitura) = rollback total.
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
    for (i, item) in pending.iter().enumerate() {
        hook(i)?;
        let stored = crypto::encrypt_field(dek, item.table, item.column, item.id, &item.plaintext)?;
        let changed = tx
            .execute(&format!("UPDATE {} SET {} = ?1 WHERE id = ?2", item.table, item.column), rusqlite::params![stored, item.id])
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("Falha ao migrar metadado: linha não encontrada.".to_string());
        }
        // Verificação de leitura: o que acabou de ser gravado tem que voltar idêntico.
        let back: String = tx
            .query_row(&format!("SELECT {} FROM {} WHERE id = ?1", item.column, item.table), [item.id], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if crypto::decrypt_field(dek, item.table, item.column, item.id, &back).as_deref() != Ok(item.plaintext.as_str()) {
            return Err("Falha ao verificar metadado migrado.".to_string());
        }
        report.migrated += 1;
    }
    tx.commit().map_err(|e| e.to_string())?;

    // 4. Incorpora o WAL ao arquivo principal e o trunca (páginas antigas do WAL deixam de existir).
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    Ok(report)
}

/// Copia o arquivo do banco (depois de um checkpoint do WAL), CIFRA com a DEK (AAD próprio) e
/// grava ao lado do `vault.db`. Nada em texto puro é escrito. Depois lê de volta, decifra e
/// compara byte a byte; só então devolve o caminho.
fn create_premigration_backup(conn: &Connection, db_path: &std::path::Path, dek: &[u8; 32]) -> Result<std::path::PathBuf, String> {
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    let snapshot = std::fs::read(db_path).map_err(|_| "Não foi possível ler o banco para o backup pré-migração.".to_string())?;
    let encrypted = crypto::encrypt_aad(dek, &snapshot, PREMIGRATION_AAD).map_err(|_| "Falha ao cifrar o backup pré-migração.".to_string())?;

    let mut target = std::path::PathBuf::from(format!("{}{}", db_path.display(), PREMIGRATION_SUFFIX));
    let mut n = 1;
    while target.exists() {
        target = std::path::PathBuf::from(format!("{}{}.{}", db_path.display(), PREMIGRATION_SUFFIX, n));
        n += 1;
    }
    let tmp = std::path::PathBuf::from(format!("{}.tmp", target.display()));
    std::fs::write(&tmp, &encrypted).map_err(|_| "Não foi possível gravar o backup pré-migração.".to_string())?;
    std::fs::rename(&tmp, &target).map_err(|_| "Não foi possível finalizar o backup pré-migração.".to_string())?;

    let verified = std::fs::read(&target)
        .ok()
        .and_then(|bytes| crypto::decrypt_aad(dek, &bytes, PREMIGRATION_AAD).ok())
        .map(|plain| plain.as_slice() == snapshot.as_slice())
        .unwrap_or(false);
    if !verified {
        let _ = std::fs::remove_file(&target);
        return Err("A verificação do backup pré-migração falhou; nada foi alterado.".to_string());
    }
    Ok(target)
}

/// Decifra um backup pré-migração com a DEK e grava o `vault.db` original em `out_path`. Não há
/// botão para isto na interface: é o procedimento de recuperação caso a migração tenha um bug.
#[allow(dead_code)]
pub fn restore_premigration_backup(backup_path: &std::path::Path, dek: &[u8; 32], out_path: &std::path::Path) -> Result<(), String> {
    let bytes = std::fs::read(backup_path).map_err(|_| "Não foi possível ler o backup pré-migração.".to_string())?;
    let plain = crypto::decrypt_aad(dek, &bytes, PREMIGRATION_AAD).map_err(|_| "Backup pré-migração inválido ou chave incorreta.".to_string())?;
    std::fs::write(out_path, plain.as_slice()).map_err(|_| "Não foi possível gravar o banco restaurado.".to_string())
}

/// Remove os backups pré-migração ao lado do banco (usado por "Excluir cofre").
pub fn remove_premigration_backups(db_path: &std::path::Path) {
    let (Some(dir), Some(name)) = (db_path.parent(), db_path.file_name().and_then(|n| n.to_str())) else { return };
    let prefix = format!("{name}{PREMIGRATION_SUFFIX}");
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Caminho do arquivo do banco de uma conexão (None em memória).
pub fn connection_db_path(conn: &Connection) -> Option<std::path::PathBuf> {
    db_file_path(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn test_dek() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn migrates_legacy_plaintext_fields_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let dek = test_dek();

        conn.execute(
            "INSERT INTO accounts (name, notes, two_factor_phone, created_at, updated_at)
             VALUES ('Conta Teste', 'SECURITY_TEST_NOTE_58321', '+55 11 90000-0000', 'now', 'now')",
            [],
        )
        .unwrap();

        let migrated_first = migrate_plaintext_account_fields(&conn, &dek).unwrap();
        assert_eq!(migrated_first, 2); // notes + two_factor_phone

        let (notes, phone): (String, String) = conn
            .query_row("SELECT notes, two_factor_phone FROM accounts", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();

        // O valor gravado não pode mais conter o texto puro original.
        assert!(!notes.contains("SECURITY_TEST_NOTE_58321"));
        assert!(!phone.contains("90000-0000"));

        // E decifra de volta corretamente com a DEK.
        let decrypted_notes = crypto::decrypt(&dek, &B64.decode(&notes).unwrap()).unwrap();
        assert_eq!(decrypted_notes.as_slice(), b"SECURITY_TEST_NOTE_58321");

        // Rodar de novo não altera nada (idempotente) — já está cifrado.
        let migrated_second = migrate_plaintext_account_fields(&conn, &dek).unwrap();
        assert_eq!(migrated_second, 0);
    }

    #[test]
    fn leaves_already_encrypted_fields_untouched() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let dek = test_dek();

        let ciphertext = B64.encode(crypto::encrypt(&dek, b"ja cifrado").unwrap());
        conn.execute(
            "INSERT INTO accounts (name, notes, created_at, updated_at) VALUES ('Conta', ?1, 'now', 'now')",
            rusqlite::params![ciphertext],
        )
        .unwrap();

        let migrated = migrate_plaintext_account_fields(&conn, &dek).unwrap();
        assert_eq!(migrated, 0);

        let stored: String = conn.query_row("SELECT notes FROM accounts", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, ciphertext);
    }

    #[test]
    fn leaves_null_and_empty_fields_untouched() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let dek = test_dek();

        conn.execute(
            "INSERT INTO accounts (name, notes, two_factor_email, created_at, updated_at)
             VALUES ('Conta', NULL, '', 'now', 'now')",
            [],
        )
        .unwrap();

        let migrated = migrate_plaintext_account_fields(&conn, &dek).unwrap();
        assert_eq!(migrated, 0);
    }

    // ------------------------------------------------------------------------------------
    // Migração de metadados para `enc:v2:` (fase 1) — somente dados fictícios
    // ------------------------------------------------------------------------------------

    const MARKERS: [&str; 7] = [
        "audit-name-7391",
        "audit-category-7391",
        "audit-user-7391",
        "audit-email-7391@example.invalid",
        "https://audit-login-7391.example.invalid",
        "https://audit-site-7391.example.invalid",
        "audit-history-detail-7391",
    ];

    /// Cofre "antigo": metadados em texto puro, como gravados antes desta versão.
    fn seed_legacy(conn: &Connection) {
        db::init_schema(conn).unwrap();
        for n in 1..=2 {
            conn.execute(
                "INSERT INTO accounts (name, category, username, email, login_url, website_url, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'now', 'now')",
                rusqlite::params![
                    format!("{}-{n}", MARKERS[0]),
                    format!("{}-{n}", MARKERS[1]),
                    format!("{}-{n}", MARKERS[2]),
                    format!("n{n}-{}", MARKERS[3]),
                    format!("{}/{n}", MARKERS[4]),
                    format!("{}/{n}", MARKERS[5]),
                ],
            )
            .unwrap();
            let id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO account_history (account_id, event, detail, created_at) VALUES (?1, 'username_changed', ?2, 'now')",
                rusqlite::params![id, format!("{}-{n}", MARKERS[6])],
            )
            .unwrap();
        }
    }

    fn raw(conn: &Connection, table: &str, column: &str) -> Vec<Option<String>> {
        let mut stmt = conn.prepare(&format!("SELECT {column} FROM {table} ORDER BY id")).unwrap();
        stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
    }

    fn all_raw_metadata(conn: &Connection) -> Vec<Option<String>> {
        METADATA_COLUMNS.iter().flat_map(|(t, c)| raw(conn, t, c)).collect()
    }

    fn scan_dir_for_markers(dir: &std::path::Path) -> Vec<String> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            for m in MARKERS {
                if bytes.windows(m.len()).any(|w| w == m.as_bytes()) {
                    found.push(m.to_string());
                }
            }
        }
        found
    }

    fn temp_vault_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cofre-mig-{}", crypto::random_bytes(6).iter().map(|b| format!("{b:02x}")).collect::<String>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn migrates_every_legacy_metadata_value_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        seed_legacy(&conn);
        let dek = test_dek();

        let report = migrate_metadata_v2(&conn, &dek).unwrap();
        assert_eq!(report.migrated, 14, "6 colunas x 2 contas + 2 históricos");
        assert_eq!((report.corrupt, report.unsupported_version, report.already_v2), (0, 0, 0));
        assert!(report.backup_path.is_none(), "banco em memória não tem arquivo para copiar");

        let after = all_raw_metadata(&conn);
        assert!(after.iter().flatten().all(|v| v.starts_with("enc:v2:")), "nenhum valor pode ficar em texto puro");
        let joined = after.iter().flatten().cloned().collect::<String>();
        assert!(MARKERS.iter().all(|m| !joined.contains(m)));
        let first: String = conn.query_row("SELECT username FROM accounts WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(crypto::decrypt_field(&dek, "accounts", "username", 1, &first), Ok("audit-user-7391-1".to_string()));

        let again = migrate_metadata_v2(&conn, &dek).unwrap();
        assert_eq!((again.migrated, again.already_v2), (0, 14));
        assert_eq!(all_raw_metadata(&conn), after, "segunda execução não pode reescrever nada (nem trocar nonces)");
    }

    #[test]
    fn values_already_in_v2_are_never_encrypted_twice() {
        let conn = Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let dek = test_dek();
        conn.execute("INSERT INTO accounts (name, created_at, updated_at) VALUES ('', 'now', 'now')", []).unwrap();
        let stored = crypto::encrypt_field(&dek, "accounts", "name", 1, "audit-name-7391").unwrap();
        conn.execute("UPDATE accounts SET name = ?1 WHERE id = 1", [&stored]).unwrap();
        let report = migrate_metadata_v2(&conn, &dek).unwrap();
        assert_eq!((report.migrated, report.already_v2), (0, 1));
        let now: String = conn.query_row("SELECT name FROM accounts WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(now, stored);
    }

    #[test]
    fn failure_in_the_middle_rolls_back_everything() {
        let conn = Connection::open_in_memory().unwrap();
        seed_legacy(&conn);
        let before = all_raw_metadata(&conn);
        let dek = test_dek();

        let result = migrate_metadata_v2_with_hook(&conn, &dek, &mut |i| if i == 5 { Err("falha simulada".to_string()) } else { Ok(()) });
        assert_eq!(result.unwrap_err(), "falha simulada");
        assert_eq!(all_raw_metadata(&conn), before, "estado parcialmente migrado não é aceitável");
        assert!(before.iter().flatten().all(|v| !v.starts_with("enc:v2:")));

        // O cofre antigo continua legível e a próxima execução (sem falha) conclui normalmente.
        assert_eq!(migrate_metadata_v2(&conn, &dek).unwrap().migrated, 14);
    }

    #[test]
    fn corrupt_unknown_version_and_copied_values_are_left_untouched_and_counted() {
        let conn = Connection::open_in_memory().unwrap();
        seed_legacy(&conn);
        let dek = test_dek();
        // conta 1: username adulterado; conta 2: e-mail com versão desconhecida; conta 2: login_url
        // com o ciphertext (válido) da conta 1 copiado para outra linha/coluna.
        let foreign = crypto::encrypt_field(&dek, "accounts", "login_url", 1, "valor-ficticio").unwrap();
        conn.execute("UPDATE accounts SET username = 'enc:v2:AAAA' WHERE id = 1", []).unwrap();
        conn.execute("UPDATE accounts SET email = 'enc:v9:conteudo-de-versao-nova' WHERE id = 2", []).unwrap();
        conn.execute("UPDATE accounts SET login_url = ?1 WHERE id = 2", [&foreign]).unwrap();

        let report = migrate_metadata_v2(&conn, &dek).unwrap();
        assert_eq!((report.corrupt, report.unsupported_version), (2, 1));
        assert_eq!(report.migrated, 14 - 3, "o resto foi migrado normalmente");
        assert_eq!(raw(&conn, "accounts", "username")[0].as_deref(), Some("enc:v2:AAAA"));
        assert_eq!(raw(&conn, "accounts", "email")[1].as_deref(), Some("enc:v9:conteudo-de-versao-nova"));
        assert_eq!(raw(&conn, "accounts", "login_url")[1].as_deref(), Some(foreign.as_str()));
    }

    #[test]
    fn file_database_gets_an_encrypted_verified_backup_and_no_marker_survives_on_disk() {
        let dir = temp_vault_dir();
        let db_path = dir.join("vault.db");
        let dek = test_dek();
        {
            let conn = Connection::open(&db_path).unwrap();
            seed_legacy(&conn);
        }
        assert!(!scan_dir_for_markers(&dir).is_empty(), "pré-condição: o cofre antigo tem os marcadores em claro");
        let original_bytes = std::fs::read(&db_path).unwrap();

        let backup_path;
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            let report = migrate_metadata_v2(&conn, &dek).unwrap();
            assert_eq!(report.migrated, 14);
            backup_path = report.backup_path.expect("deveria ter criado backup antes de migrar");
            // Com a conexão AINDA aberta (WAL ativo): nenhum marcador em nenhum arquivo, inclusive -wal e o backup.
            assert_eq!(scan_dir_for_markers(&dir), Vec::<String>::new(), "marcadores em claro após migrar (conexão aberta)");
        }
        assert_eq!(scan_dir_for_markers(&dir), Vec::<String>::new(), "marcadores em claro após migrar (conexão fechada)");

        // O backup é recuperável com a DEK e reproduz o cofre antigo (que tinha o texto puro).
        let restored = dir.join("restored.db");
        restore_premigration_backup(&backup_path, &dek, &restored).unwrap();
        let restored_conn = Connection::open(&restored).unwrap();
        let legacy_name: String = restored_conn.query_row("SELECT name FROM accounts WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(legacy_name, "audit-name-7391-1");
        assert_eq!(std::fs::read(&backup_path).unwrap().windows(15).any(|w| w == b"audit-name-7391"), false);
        assert!(restore_premigration_backup(&backup_path, &[1u8; 32], &dir.join("x.db")).is_err(), "chave errada não abre o backup");
        assert!(original_bytes.len() > 0);

        // Segunda execução: nada a migrar → não cria outro backup.
        let conn = Connection::open(&db_path).unwrap();
        let again = migrate_metadata_v2(&conn, &dek).unwrap();
        assert_eq!((again.migrated, again.backup_path), (0, None));
        drop(conn);
        drop(restored_conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failure_after_backup_leaves_the_database_file_untouched() {
        let dir = temp_vault_dir();
        let db_path = dir.join("vault.db");
        let dek = test_dek();
        {
            let conn = Connection::open(&db_path).unwrap();
            seed_legacy(&conn);
        }
        let conn = Connection::open(&db_path).unwrap();
        let before = all_raw_metadata(&conn);
        assert!(migrate_metadata_v2_with_hook(&conn, &dek, &mut |i| if i == 2 { Err("falha".into()) } else { Ok(()) }).is_err());
        assert_eq!(all_raw_metadata(&conn), before);
        drop(conn);
        // O backup criado antes da falha existe, é cifrado e recuperável.
        let backups: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains(".pre-v2.bak")).collect();
        assert_eq!(backups.len(), 1);
        remove_premigration_backups(&db_path);
        assert!(!std::fs::read_dir(&dir).unwrap().flatten().any(|e| e.file_name().to_string_lossy().contains(".pre-v2.bak")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlocking_an_old_vault_migrates_it_and_unlock_survives_a_migration_failure() {
        let conn = Connection::open_in_memory().unwrap();
        seed_legacy(&conn);
        let params = crypto::KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let kek = crypto::derive_key("senha-mestra", &salt, &params).unwrap();
        let dek = test_dek();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, NULL, 'now')",
            rusqlite::params![salt, serde_json::to_string(&params).unwrap(), crypto::encrypt(&kek, &dek).unwrap()],
        )
        .unwrap();

        let state = crate::state::VaultState::new();
        crate::commands::vault::unlock_vault_core(&conn, &state, &zeroize::Zeroizing::new("senha-mestra".to_string())).unwrap();
        assert!(state.is_unlocked());
        assert!(all_raw_metadata(&conn).iter().flatten().all(|v| v.starts_with("enc:v2:")), "o desbloqueio migra o cofre antigo");

        // Uma falha de migração nunca impede o desbloqueio (migrate_all engole o erro, só loga).
        conn.execute("DROP TABLE account_history", []).unwrap();
        assert!(migrate_all(&conn, &dek).is_ok());
    }

    #[test]
    fn every_unlock_path_runs_the_full_migration_and_no_code_logs_personal_data() {
        for (name, src) in [
            ("vault.rs", include_str!("commands/vault.rs")),
            ("recovery_key.rs", include_str!("commands/recovery_key.rs")),
            ("security_questions.rs", include_str!("commands/security_questions.rs")),
        ] {
            assert!(src.contains("crate::migration::migrate_all(conn, &dek)"), "{name} deve chamar migrate_all");
            assert!(!src.contains("crate::migration::migrate_plaintext_account_fields(conn, &dek)"), "{name} ainda chama só a migração antiga");
        }
        // Qualquer macro de log em código de produção só pode ser a de native_lock/migration (que
        // imprimem contagens e mensagens técnicas fixas, nunca valores de campos).
        for (name, src) in [
            ("accounts.rs", include_str!("commands/accounts.rs")),
            ("history.rs", include_str!("commands/history.rs")),
            ("crypto.rs", include_str!("crypto.rs")),
            ("db.rs", include_str!("db.rs")),
            ("backup.rs", include_str!("commands/backup.rs")),
        ] {
            let production = src.split("#[cfg(test)]\nmod tests").next().unwrap();
            for mac in ["println!", "eprintln!", "dbg!", "log::", "tracing::"] {
                assert!(!production.contains(mac), "{name} não pode usar {mac} em código de produção");
            }
        }
    }
}
