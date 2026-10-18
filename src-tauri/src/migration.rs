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
}
