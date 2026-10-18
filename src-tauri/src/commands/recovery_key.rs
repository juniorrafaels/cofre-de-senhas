use crate::crypto::{self, KdfParams};
use crate::db;
use crate::state::VaultState;
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

/// Reaproveita o mesmo marcador de verificação usado por `vault_meta.dek_check`
/// (ver `security_questions::compute_dek_check`) — é só `encrypt(dek, marcador_fixo)`.
const DEK_CHECK_PLAINTEXT: &[u8] = b"vault-dek-check-v1";

fn generic_error() -> String {
    "Não foi possível concluir a operação.".to_string()
}

#[derive(Serialize)]
pub struct RecoveryKeyStatus {
    pub enabled: bool,
    pub created_at: Option<String>,
}

#[tauri::command]
pub fn recovery_key_status(app: AppHandle) -> Result<RecoveryKeyStatus, String> {
    let conn = db::open(&app)?;
    let row: Option<(Option<Vec<u8>>, Option<String>)> = conn
        .query_row(
            "SELECT recovery_key_wrapped_dek, recovery_key_created_at FROM vault_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();
    match row {
        Some((Some(_), created_at)) => Ok(RecoveryKeyStatus { enabled: true, created_at }),
        _ => Ok(RecoveryKeyStatus { enabled: false, created_at: None }),
    }
}

/// Lógica pura de `generate_recovery_key`, recebendo a DEK já obtida do `state` — extraída para
/// permitir testar a reautenticação (senha mestra atual errada/certa) e o wrap/unwrap real da
/// Recovery Key sem precisar de um `AppHandle`/`State` reais (mesmo padrão de
/// `security_questions::attempt_recovery_core`).
fn generate_recovery_key_core(conn: &rusqlite::Connection, current_password: &Zeroizing<String>, dek: [u8; 32]) -> Result<String, String> {
    crate::commands::vault::verify_current_password(conn, current_password)?;

    let recovery_key = crypto::generate_recovery_key();
    let normalized = Zeroizing::new(crypto::normalize_recovery_key(&recovery_key));

    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let params = KdfParams::default();
    let kek2 = crypto::derive_key(&normalized, &salt, &params).map_err(|_| generic_error())?;
    let wrapped_dek = crypto::encrypt(&kek2, &dek).map_err(|_| generic_error())?;
    let check = crypto::encrypt(&dek, DEK_CHECK_PLAINTEXT).map_err(|_| generic_error())?;
    let params_json = serde_json::to_string(&params).map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE vault_meta SET recovery_key_salt = ?1, recovery_key_kdf_params = ?2, recovery_key_wrapped_dek = ?3, recovery_key_check = ?4, recovery_key_created_at = ?5 WHERE id = 1",
        rusqlite::params![salt, params_json, wrapped_dek, check, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;

    Ok(recovery_key)
}

/// Gera uma nova Recovery Key e a torna um segundo caminho independente para desembrulhar a
/// mesma DEK (ver `crypto::generate_recovery_key` — 120 bits de entropia, sem depender de
/// nenhuma informação sobre o usuário). Regenerar invalida qualquer chave anterior. A chave em
/// texto puro só é retornada UMA VEZ aqui — nunca é persistida em lugar nenhum.
///
/// Fase 4 (SECURITY_AUDIT_PHASE_4.md): exige a senha mestra atual, reverificada neste mesmo
/// comando (não um flag "já reautenticado" que a WebView poderia falsificar) — gerar/substituir
/// a Recovery Key é uma operação crítica o bastante (ela sozinha desembrulha a DEK) para não
/// depender só de `state.is_unlocked()`.
#[tauri::command]
pub fn generate_recovery_key(app: AppHandle, state: State<VaultState>, current_password: String) -> Result<String, String> {
    let current_password = Zeroizing::new(current_password);
    let dek = state.with_dek(|dek| *dek).ok_or_else(|| "O cofre está bloqueado.".to_string())?;
    let conn = db::open(&app)?;
    generate_recovery_key_core(&conn, &current_password, dek)
}

/// Fase 4: também exige reautenticação por senha mestra (ver `generate_recovery_key`) — desativar
/// a Recovery Key destrói um mecanismo de recuperação, não é uma ação reversível de UI comum.
#[tauri::command]
pub fn disable_recovery_key(app: AppHandle, state: State<VaultState>, current_password: String) -> Result<(), String> {
    let current_password = Zeroizing::new(current_password);
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    let conn = db::open(&app)?;
    crate::commands::vault::verify_current_password(&conn, &current_password)?;
    conn.execute(
        "UPDATE vault_meta SET recovery_key_salt = NULL, recovery_key_kdf_params = NULL, recovery_key_wrapped_dek = NULL, recovery_key_check = NULL, recovery_key_created_at = NULL WHERE id = 1",
        [],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Lógica pura de `unlock_with_recovery_key` — recebe a `Connection` e devolve a DEK reconstruída
/// em vez de chamar `state.set_dek` diretamente, para poder ser testada de ponta a ponta (chave
/// certa recupera a DEK real; chave errada falha sem tocar em `vault_meta`) sem `AppHandle`/
/// `State` reais.
fn unlock_with_recovery_key_core(conn: &rusqlite::Connection, recovery_key: &Zeroizing<String>) -> Result<[u8; 32], String> {
    let row: (Option<Vec<u8>>, Option<String>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT recovery_key_salt, recovery_key_kdf_params, recovery_key_wrapped_dek FROM vault_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "O cofre ainda não foi criado.".to_string())?;

    let (Some(salt), Some(params_json), Some(wrapped_dek)) = row else {
        return Err("Nenhuma Recovery Key foi configurada para este cofre.".to_string());
    };

    let params: KdfParams = serde_json::from_str(&params_json).map_err(|_| generic_error())?;
    let normalized = Zeroizing::new(crypto::normalize_recovery_key(recovery_key));
    let kek2 = crypto::derive_key(&normalized, &salt, &params).map_err(|_| generic_error())?;
    let dek_bytes = crypto::decrypt(&kek2, &wrapped_dek).map_err(|_| "Recovery Key incorreta.".to_string())?;

    if dek_bytes.len() != 32 {
        return Err("Recovery Key incorreta.".to_string());
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);

    // Auto-cura (Fase 2): este também é um caminho independente para obter a DEK.
    crate::migration::migrate_plaintext_account_fields(conn, &dek)?;

    Ok(dek)
}

/// Desbloqueia o cofre a partir da Recovery Key — caminho independente de `unlock_vault`
/// (senha mestra) e de `attempt_vault_recovery` (perguntas de segurança), mas que resulta na
/// mesma DEK. Falha genérica em qualquer etapa, exatamente como `unlock_vault`.
#[tauri::command]
pub fn unlock_with_recovery_key(app: AppHandle, state: State<VaultState>, recovery_key: String) -> Result<(), String> {
    let recovery_key = Zeroizing::new(recovery_key);
    let conn = db::open(&app)?;
    unlock_with_recovery_key_into_state(&conn, &state, &recovery_key)
}

/// Desbloqueia via Recovery Key e marca a sessão como "aberta por recuperação" — o único estado
/// em que `reset_master_password_after_recovery` aceita trocar a senha mestra sem a atual.
pub(crate) fn unlock_with_recovery_key_into_state(
    conn: &rusqlite::Connection,
    state: &VaultState,
    recovery_key: &Zeroizing<String>,
) -> Result<(), String> {
    let dek = unlock_with_recovery_key_core(conn, recovery_key)?;
    state.set_dek_from_recovery(dek);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::VaultState;

    fn test_params() -> KdfParams {
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn generate_requires_unlocked_vault() {
        let state = VaultState::new();
        assert!(!state.is_unlocked());
        // A própria checagem que `generate_recovery_key` faz antes de tocar no banco.
        assert!(state.with_dek(|dek| *dek).is_none());
    }

    /// Cofre sintético com senha mestra + Recovery Key já geradas — para exercitar o caminho de
    /// desbloqueio por Recovery Key de ponta a ponta (seção 15/16/17 do pedido de validação final).
    fn fixture_vault_with_recovery_key(master_password: &str) -> (rusqlite::Connection, [u8; 32], String) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();

        let dek = [11u8; 32];
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let params = test_params();
        let kek = crypto::derive_key(master_password, &salt, &params).unwrap();
        let wrapped_dek = crypto::encrypt(&kek, &dek).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                salt,
                serde_json::to_string(&params).unwrap(),
                wrapped_dek,
                crate::commands::security_questions::compute_dek_check(&dek).unwrap(),
                db::now_iso(),
            ],
        )
        .unwrap();

        let recovery_key =
            generate_recovery_key_core(&conn, &Zeroizing::new(master_password.to_string()), dek).unwrap();
        (conn, dek, recovery_key)
    }

    // Seção 15 do pedido: gerar uma Recovery Key e usá-la para desbloquear deve devolver
    // exatamente a mesma DEK que a senha mestra desembrulharia — os mesmos dados, não uma cópia.
    #[test]
    fn correct_recovery_key_unlocks_and_recovers_the_real_dek() {
        let (conn, dek, recovery_key) = fixture_vault_with_recovery_key("senha-mestra-XSS_TEST");
        let recovered = unlock_with_recovery_key_core(&conn, &Zeroizing::new(recovery_key)).unwrap();
        assert_eq!(recovered, dek);
    }

    // Seção 16 do pedido: Recovery Key incorreta falha de forma limpa — sem corromper
    // `vault_meta`, sem "quase" desbloquear, sem alterar a Recovery Key real configurada.
    #[test]
    fn wrong_recovery_key_fails_cleanly_without_altering_vault_meta() {
        let (conn, _dek, recovery_key) = fixture_vault_with_recovery_key("senha-mestra-XSS_TEST");

        let mut wrong = recovery_key.clone();
        // Troca o último caractere por outro símbolo válido do alfabeto — uma chave "quase certa",
        // não uma string aleatória sem forma nenhuma.
        wrong.pop();
        wrong.push(if recovery_key.ends_with('0') { '1' } else { '0' });

        let wrapped_dek_before: Vec<u8> =
            conn.query_row("SELECT recovery_key_wrapped_dek FROM vault_meta WHERE id = 1", [], |r| r.get(0)).unwrap();

        let result = unlock_with_recovery_key_core(&conn, &Zeroizing::new(wrong));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Recovery Key incorreta.");

        let wrapped_dek_after: Vec<u8> =
            conn.query_row("SELECT recovery_key_wrapped_dek FROM vault_meta WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(wrapped_dek_before, wrapped_dek_after, "uma tentativa errada não pode alterar a Recovery Key gravada");
    }

    // Seção 17 do pedido: gerar/desativar a Recovery Key com o cofre desbloqueado ainda exige a
    // senha mestra ATUAL correta — reverificada de verdade contra `wrapped_dek`, não um flag.
    #[test]
    fn generating_a_new_recovery_key_rejects_wrong_current_password() {
        let (conn, dek, first_key) = fixture_vault_with_recovery_key("senha-mestra-XSS_TEST");
        let err = generate_recovery_key_core(&conn, &Zeroizing::new("senha-errada".to_string()), dek).unwrap_err();
        assert!(!err.is_empty());

        // A Recovery Key original continua sendo a única válida (não foi substituída).
        let original_key_still_works = unlock_with_recovery_key_core(&conn, &Zeroizing::new(first_key)).is_ok();
        assert!(original_key_still_works, "uma tentativa de gerar nova chave com senha errada não pode invalidar a antiga");
    }

    #[test]
    fn generating_a_new_recovery_key_with_correct_password_invalidates_the_old_one() {
        let (conn, dek, first_key) = fixture_vault_with_recovery_key("senha-mestra-XSS_TEST");
        let second_key =
            generate_recovery_key_core(&conn, &Zeroizing::new("senha-mestra-XSS_TEST".to_string()), dek).unwrap();
        assert_ne!(first_key, second_key);

        assert!(unlock_with_recovery_key_core(&conn, &Zeroizing::new(first_key)).is_err(), "a chave antiga deve parar de funcionar");
        assert_eq!(unlock_with_recovery_key_core(&conn, &Zeroizing::new(second_key)).unwrap(), dek);
    }

    // Item B da auditoria: o fluxo legítimo "esqueci a senha → Recovery Key → nova senha" continua
    // funcionando, e só ele (não uma sessão normal) libera o reset sem a senha atual.
    #[test]
    fn recovery_key_unlock_allows_reset_and_new_password_unlocks_with_same_dek() {
        let (conn, dek, recovery_key) = fixture_vault_with_recovery_key("senha-mestra-antiga");
        let secret_ciphertext = crypto::encrypt_to_base64(&dek, "SECURITY_TEST_SECRET_88412").unwrap();

        let state = VaultState::new();
        unlock_with_recovery_key_into_state(&conn, &state, &Zeroizing::new(recovery_key.clone())).unwrap();
        assert_eq!(state.unlock_method(), Some(crate::state::UnlockMethod::Recovery));

        let new_password = Zeroizing::new("nova-senha-mestra".to_string());
        crate::commands::security_questions::reset_master_password_core(&conn, &state, &new_password, &test_params()).unwrap();

        state.clear();
        assert!(!state.is_unlocked());
        assert!(crate::commands::vault::unlock_vault_core(&conn, &state, &Zeroizing::new("senha-mestra-antiga".to_string())).is_err());
        crate::commands::vault::unlock_vault_core(&conn, &state, &new_password).unwrap();
        assert_eq!(state.with_dek(|d| *d), Some(dek));
        assert_eq!(state.unlock_method(), Some(crate::state::UnlockMethod::MasterPassword));
        let plaintext = state.with_dek(|d| crypto::decrypt_from_base64(d, &secret_ciphertext)).unwrap().unwrap();
        assert_eq!(plaintext, "SECURITY_TEST_SECRET_88412");

        // A Recovery Key continua válida depois da troca (ela embrulha a mesma DEK).
        assert_eq!(unlock_with_recovery_key_core(&conn, &Zeroizing::new(recovery_key)).unwrap(), dek);
    }

    #[test]
    fn wrong_recovery_key_does_not_open_a_recovery_session() {
        let (conn, _dek, _key) = fixture_vault_with_recovery_key("senha-mestra-antiga");
        let state = VaultState::new();
        assert!(unlock_with_recovery_key_into_state(&conn, &state, &Zeroizing::new("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA".to_string())).is_err());
        assert!(!state.is_unlocked());
        assert!(crate::commands::security_questions::reset_master_password_core(
            &conn,
            &state,
            &Zeroizing::new("nova-senha-mestra".to_string()),
            &test_params()
        )
        .is_err());
    }
}
