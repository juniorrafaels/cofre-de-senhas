//! Segunda senha de recuperação (opcional): um terceiro caminho para obter a MESMA DEK, independente
//! do desbloqueio normal, da Recovery Key e das perguntas de segurança (Shamir).
//!
//! # Formato
//!
//! `KEK_r = Argon2id(senha_de_recuperação, recovery_pw_salt, recovery_pw_kdf_params)` e
//! `recovery_pw_wrapped_dek = XChaCha20-Poly1305(KEK_r, DEK, AAD = contexto || len(salt) || salt)`
//! (nonce aleatório de 24 bytes). Salt exclusivo por configuração, parâmetros versionados e
//! validados contra os limites do KDF. Nada da senha é armazenado.
//!
//! # Por que não depende do desbloqueio normal
//!
//! O envelope guarda a DEK diretamente (como a Recovery Key), então a recuperação funciona com o
//! cofre bloqueado e mesmo que a senha mestra (ou uma das duas senhas) tenha sido perdida. Como a
//! DEK nunca é rotacionada por trocas de credencial, ativar/trocar/desativar este método NÃO toca
//! na Recovery Key nem nas perguntas de segurança, e vice-versa: cada um é um envelope separado.
//!
//! # Operações sensíveis
//!
//! Ativar, trocar e desativar exigem o cofre desbloqueado E a reautenticação das credenciais atuais
//! (uma ou duas senhas), no próprio comando, com bloqueio progressivo se estiver ativado. A
//! tentativa de recuperação usa o escopo de bloqueio próprio `recovery_password`.

use crate::auth::{self, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS};
use crate::commands::vault::opt_secret;
use crate::crypto::{self, KdfParams};
use crate::db;
use crate::lockout::{self, Clock, SystemClock};
use crate::state::{UnlockMethod, VaultState};
use rusqlite::{params, Connection};
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

const AAD_CONTEXT: &[u8] = b"cofre/recovery-password/v1";
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;

pub const MSG_NOT_CONFIGURED: &str =
    "Nenhuma segunda senha de recuperação foi configurada para este cofre.";
pub const MSG_WRONG: &str = "Segunda senha de recuperação incorreta.";
pub const MSG_CORRUPT: &str = "Os dados da segunda senha de recuperação estão corrompidos.";
pub const MSG_TOO_SHORT: &str = "A segunda senha de recuperação deve ter pelo menos 8 caracteres.";
pub const MSG_SAME_AS_UNLOCK: &str =
    "A senha de recuperação precisa ser diferente das senhas de desbloqueio.";
pub const MSG_LOCKED_VAULT: &str = "O cofre está bloqueado.";

#[derive(Serialize)]
pub struct RecoveryPasswordStatus {
    pub enabled: bool,
    pub created_at: Option<String>,
}

fn aad(salt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_CONTEXT.len() + salt.len() + 8);
    out.extend_from_slice(&(AAD_CONTEXT.len() as u32).to_be_bytes());
    out.extend_from_slice(AAD_CONTEXT);
    out.extend_from_slice(&(salt.len() as u32).to_be_bytes());
    out.extend_from_slice(salt);
    out
}

fn validate_recovery_password(password: &str) -> Result<(), String> {
    let chars = password.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err(MSG_TOO_SHORT.to_string());
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(auth::MSG_PASSWORD_TOO_LONG.to_string());
    }
    Ok(())
}

/// Colunas do envelope, todas ou nenhuma. Parcial = corrompido.
type Envelope = (
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
);

fn read_envelope(conn: &Connection) -> Result<Envelope, String> {
    conn.query_row(
        "SELECT recovery_pw_salt, recovery_pw_kdf_params, recovery_pw_wrapped_dek, recovery_pw_created_at FROM vault_meta WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => auth::MSG_NOT_CREATED.to_string(),
        rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::FromSqlConversionFailure(..) => MSG_CORRUPT.to_string(),
        _ => auth::MSG_GENERIC.to_string(),
    })
}

pub fn status_core(conn: &Connection) -> Result<RecoveryPasswordStatus, String> {
    let (salt, params_json, wrapped, created_at) = read_envelope(conn)?;
    let enabled = salt.is_some() || params_json.is_some() || wrapped.is_some();
    Ok(RecoveryPasswordStatus {
        enabled,
        created_at: if enabled { created_at } else { None },
    })
}

#[tauri::command]
pub fn recovery_password_status(app: AppHandle) -> Result<RecoveryPasswordStatus, String> {
    let conn = db::open(&app)?;
    status_core(&conn)
}

/// Ativa ou TROCA a segunda senha de recuperação. Reautentica as credenciais atuais.
pub fn set_recovery_password_core(
    conn: &Connection,
    current_password: &Zeroizing<String>,
    current_password2: Option<&Zeroizing<String>>,
    new_recovery_password: &Zeroizing<String>,
    kdf: &KdfParams,
    clock: &dyn Clock,
) -> Result<(), String> {
    validate_recovery_password(new_recovery_password)?;
    if new_recovery_password.as_str() == current_password.as_str()
        || current_password2.is_some_and(|p| p.as_str() == new_recovery_password.as_str())
    {
        return Err(MSG_SAME_AS_UNLOCK.to_string());
    }
    let dek = auth::authenticate(
        conn,
        current_password,
        current_password2.map(|p| p.as_str()),
        clock,
    )
    .map_err(|e| e.to_ipc())?;

    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let kek = crypto::derive_key(new_recovery_password, &salt, kdf)
        .map_err(|_| auth::MSG_GENERIC.to_string())?;
    let wrapped =
        crypto::encrypt_aad(&kek, &dek, &aad(&salt)).map_err(|_| auth::MSG_GENERIC.to_string())?;
    let params_json = serde_json::to_string(kdf).map_err(|e| e.to_string())?;

    // Uma única UPDATE dentro de transação + releitura/verificação antes do COMMIT: ou o envelope
    // novo funciona, ou o anterior (ativo ou ausente) continua exatamente como estava.
    auth::in_immediate_tx(conn, || {
        let changed = conn
            .execute(
                "UPDATE vault_meta SET recovery_pw_salt = ?1, recovery_pw_kdf_params = ?2, recovery_pw_wrapped_dek = ?3, \
                 recovery_pw_created_at = ?4 WHERE id = 1",
                params![salt, params_json, wrapped, db::now_iso()],
            )
            .map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err(auth::MSG_NOT_CREATED.to_string());
        }
        match unwrap_core(conn, new_recovery_password, &SilentClock) {
            Ok(check) if check == dek => Ok(()),
            _ => Err(auth::MSG_GENERIC.to_string()),
        }
    })
}

/// Relógio sem efeito: a releitura de verificação não passa pelo bloqueio progressivo.
struct SilentClock;
impl Clock for SilentClock {
    fn now_ms(&self) -> i64 {
        0
    }
}

pub fn disable_recovery_password_core(
    conn: &Connection,
    current_password: &Zeroizing<String>,
    current_password2: Option<&Zeroizing<String>>,
    clock: &dyn Clock,
) -> Result<(), String> {
    auth::authenticate(
        conn,
        current_password,
        current_password2.map(|p| p.as_str()),
        clock,
    )
    .map_err(|e| e.to_ipc())?;
    conn.execute(
        "UPDATE vault_meta SET recovery_pw_salt = NULL, recovery_pw_kdf_params = NULL, recovery_pw_wrapped_dek = NULL, \
         recovery_pw_created_at = NULL WHERE id = 1",
        [],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Desembrulha a DEK com a senha de recuperação, SEM bloqueio progressivo (uso interno e de testes;
/// o caminho de usuário é `unlock_with_recovery_password_core`).
fn unwrap_core(
    conn: &Connection,
    recovery_password: &str,
    _clock: &dyn Clock,
) -> Result<[u8; 32], String> {
    let (salt, params_json, wrapped, _) = read_envelope(conn)?;
    let (salt, params_json, wrapped) = match (salt, params_json, wrapped) {
        (None, None, None) => return Err(MSG_NOT_CONFIGURED.to_string()),
        (Some(s), Some(p), Some(w)) => (s, p, w),
        _ => return Err(MSG_CORRUPT.to_string()), // envelope parcial
    };
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(MSG_CORRUPT.to_string());
    }
    let kdf: KdfParams = serde_json::from_str(&params_json).map_err(|_| MSG_CORRUPT.to_string())?;
    if !kdf.is_within_bounds() {
        return Err(MSG_CORRUPT.to_string());
    }
    let kek = crypto::derive_key(recovery_password, &salt, &kdf)
        .map_err(|_| auth::MSG_GENERIC.to_string())?;
    let plain =
        crypto::decrypt_aad(&kek, &wrapped, &aad(&salt)).map_err(|_| MSG_WRONG.to_string())?;
    if plain.len() != 32 {
        return Err(MSG_CORRUPT.to_string());
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plain);
    Ok(dek)
}

/// Recuperação: formato → configuração/estrutura → bloqueio progressivo (cobra a tentativa) →
/// derivação/decifragem. Só "senha incorreta" mantém a cobrança; configuração ausente, formato
/// inválido e dados corrompidos NÃO contam como tentativa.
pub fn unlock_with_recovery_password_core(
    conn: &Connection,
    recovery_password: &Zeroizing<String>,
    clock: &dyn Clock,
) -> Result<[u8; 32], String> {
    validate_recovery_password(recovery_password)?;
    // Falha cedo (sem gastar tentativa) se não há envelope utilizável.
    {
        let (salt, params_json, wrapped, _) = read_envelope(conn)?;
        match (&salt, &params_json, &wrapped) {
            (None, None, None) => return Err(MSG_NOT_CONFIGURED.to_string()),
            (Some(_), Some(_), Some(_)) => {}
            _ => return Err(MSG_CORRUPT.to_string()),
        }
    }
    let ticket =
        lockout::begin(conn, lockout::SCOPE_RECOVERY_PASSWORD, clock).map_err(|e| match e {
            lockout::ThrottleError::Locked {
                remaining_ms,
                failed_count,
            } => auth::locked_ipc(remaining_ms, failed_count),
            lockout::ThrottleError::Internal(_) => auth::MSG_GENERIC.to_string(),
        })?;
    match unwrap_core(conn, recovery_password, clock) {
        Ok(dek) => {
            ticket.succeed(conn);
            Ok(dek)
        }
        Err(msg) if msg == MSG_WRONG => Err(msg),
        Err(other) => {
            ticket.refund(conn);
            Err(other)
        }
    }
}

#[tauri::command]
pub fn set_recovery_password(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    current_password2: Option<String>,
    new_recovery_password: String,
) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err(MSG_LOCKED_VAULT.to_string());
    }
    let current_password = Zeroizing::new(current_password);
    let current_password2 = opt_secret(current_password2);
    let new_recovery_password = Zeroizing::new(new_recovery_password);
    let conn = db::open(&app)?;
    set_recovery_password_core(
        &conn,
        &current_password,
        current_password2.as_ref(),
        &new_recovery_password,
        &KdfParams::default(),
        &SystemClock,
    )
}

#[tauri::command]
pub fn disable_recovery_password(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    current_password2: Option<String>,
) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err(MSG_LOCKED_VAULT.to_string());
    }
    let current_password = Zeroizing::new(current_password);
    let current_password2 = opt_secret(current_password2);
    let conn = db::open(&app)?;
    disable_recovery_password_core(
        &conn,
        &current_password,
        current_password2.as_ref(),
        &SystemClock,
    )
}

/// Desbloqueia pela segunda senha de recuperação e marca a sessão como "aberta por recuperação"
/// (permite redefinir a senha mestra sem a atual — e volta o desbloqueio a uma senha).
pub(crate) fn unlock_with_recovery_password_into_state(
    conn: &Connection,
    state: &VaultState,
    recovery_password: &Zeroizing<String>,
    clock: &dyn Clock,
) -> Result<(), String> {
    let reservation = state.reserve_exclusive()?;
    let dek = unlock_with_recovery_password_core(conn, recovery_password, clock)?;
    crate::migration::migrate_all(conn, &dek)?;
    state.commit(dek, UnlockMethod::Recovery, reservation)
}

#[tauri::command]
pub fn unlock_with_recovery_password(
    app: AppHandle,
    state: State<VaultState>,
    recovery_password: String,
) -> Result<(), String> {
    let recovery_password = Zeroizing::new(recovery_password);
    let conn = db::open(&app)?;
    unlock_with_recovery_password_into_state(&conn, &state, &recovery_password, &SystemClock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{fast_params, legacy_vault, TestClock};
    use crate::commands::{recovery_key, security_questions};
    use std::cell::Cell;

    const DEK: [u8; 32] = [21u8; 32];

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    fn setup() -> Connection {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-abc-1"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        conn
    }

    #[test]
    fn status_reflects_enabled_disabled_and_legacy_vaults() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        let st = status_core(&conn).unwrap();
        assert!(
            !st.enabled && st.created_at.is_none(),
            "cofre legado: método desativado por padrão"
        );
        set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-abc-1"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        let st = status_core(&conn).unwrap();
        assert!(st.enabled && st.created_at.is_some());
        disable_recovery_password_core(&conn, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert!(!status_core(&conn).unwrap().enabled);
    }

    #[test]
    fn correct_second_password_recovers_the_same_dek_and_wrong_ones_are_rejected() {
        let conn = setup();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Ok(DEK)
        );
        for wrong in [
            "recuperacao-abc-2",
            "senha-mestra-xyz",
            "RECUPERACAO-ABC-1",
            "recuperacao-abc-1 ",
        ] {
            assert_eq!(
                unlock_with_recovery_password_core(&conn, &pw(wrong), &SystemClock),
                Err(MSG_WRONG.to_string()),
                "{wrong}"
            );
        }
    }

    #[test]
    fn invalid_format_missing_configuration_and_corruption_have_distinct_clear_errors() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("curta"), &SystemClock),
            Err(MSG_TOO_SHORT.to_string())
        );
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_NOT_CONFIGURED.to_string())
        );

        let conn = setup();
        conn.execute(
            "UPDATE vault_meta SET recovery_pw_kdf_params = 'nao-json'",
            [],
        )
        .unwrap();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_CORRUPT.to_string())
        );
        conn.execute("UPDATE vault_meta SET recovery_pw_kdf_params = '{\"memory_kib\":4294967295,\"iterations\":1,\"parallelism\":1}'", []).unwrap();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_CORRUPT.to_string())
        );

        let conn = setup();
        conn.execute("UPDATE vault_meta SET recovery_pw_wrapped_dek = NULL", [])
            .unwrap();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_CORRUPT.to_string()),
            "envelope parcial"
        );

        let conn = setup();
        conn.execute(
            "UPDATE vault_meta SET recovery_pw_wrapped_dek = zeroblob(60)",
            [],
        )
        .unwrap();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_WRONG.to_string()),
            "adulterado não autentica"
        );
    }

    #[test]
    fn the_envelope_is_bound_to_its_salt_context() {
        let conn = setup();
        // Trocar o salt por outro (mesmo tamanho) quebra a autenticação: o AAD amarra o contexto.
        conn.execute(
            "UPDATE vault_meta SET recovery_pw_salt = randomblob(16)",
            [],
        )
        .unwrap();
        assert!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock)
                .is_err()
        );
    }

    #[test]
    fn setting_requires_current_credentials_and_a_valid_distinct_password() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        let before: Option<Vec<u8>> = conn
            .query_row("SELECT recovery_pw_wrapped_dek FROM vault_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(set_recovery_password_core(
            &conn,
            &pw("senha-errada-123"),
            None,
            &pw("recuperacao-abc-1"),
            &fast_params(),
            &SystemClock
        )
        .is_err());
        assert_eq!(
            set_recovery_password_core(
                &conn,
                &pw("senha-mestra-xyz"),
                None,
                &pw("curta"),
                &fast_params(),
                &SystemClock
            ),
            Err(MSG_TOO_SHORT.to_string())
        );
        assert_eq!(
            set_recovery_password_core(
                &conn,
                &pw("senha-mestra-xyz"),
                None,
                &pw("senha-mestra-xyz"),
                &fast_params(),
                &SystemClock
            ),
            Err(MSG_SAME_AS_UNLOCK.to_string())
        );
        let after: Option<Vec<u8>> = conn
            .query_row("SELECT recovery_pw_wrapped_dek FROM vault_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(before, after);
        assert!(
            disable_recovery_password_core(&conn, &pw("senha-errada-123"), None, &SystemClock)
                .is_err()
        );
    }

    #[test]
    fn changing_the_second_password_invalidates_the_old_one_only() {
        let conn = setup();
        set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-nova-2"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        assert!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock)
                .is_err()
        );
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-nova-2"), &SystemClock),
            Ok(DEK)
        );
    }

    #[test]
    fn disabling_removes_the_method_without_touching_unlock() {
        let conn = setup();
        disable_recovery_password_core(&conn, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Err(MSG_NOT_CONFIGURED.to_string())
        );
        assert_eq!(
            crate::auth::unwrap_dek(&conn, "senha-mestra-xyz", None),
            Ok(DEK)
        );
    }

    #[test]
    fn it_works_with_the_vault_locked_and_with_the_master_password_lost() {
        let conn = setup();
        // Estado fresco: nenhuma sessão, nenhuma DEK em memória; só o banco.
        let state = VaultState::new();
        assert!(!state.is_unlocked());
        unlock_with_recovery_password_into_state(
            &conn,
            &state,
            &pw("recuperacao-abc-1"),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(state.unlock_method(), Some(UnlockMethod::Recovery));
        // Sessão de recuperação permite redefinir a senha mestra SEM a antiga, preservando a DEK.
        security_questions::reset_master_password_core(
            &conn,
            &state,
            &pw("senha-nova-xyz-1"),
            &fast_params(),
        )
        .unwrap();
        assert_eq!(
            crate::auth::unwrap_dek(&conn, "senha-nova-xyz-1", None),
            Ok(DEK)
        );
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Ok(DEK),
            "o método continua válido"
        );
    }

    #[test]
    fn it_works_when_two_password_unlock_is_enabled_and_both_unlock_passwords_are_lost() {
        let conn = setup();
        crate::auth::enable_dual(
            &conn,
            "senha-mestra-xyz",
            "segunda-senha-abc",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        // Recuperação independente da política: não precisa de nenhuma das duas senhas de desbloqueio.
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Ok(DEK)
        );
        let state = VaultState::new();
        unlock_with_recovery_password_into_state(
            &conn,
            &state,
            &pw("recuperacao-abc-1"),
            &SystemClock,
        )
        .unwrap();
        security_questions::reset_master_password_core(
            &conn,
            &state,
            &pw("senha-redefinida-9"),
            &fast_params(),
        )
        .unwrap();
        assert_eq!(
            crate::auth::read_policy(&conn),
            Ok(crate::auth::UnlockPolicy::Single)
        );
    }

    #[test]
    fn it_coexists_with_recovery_key_and_security_questions() {
        let conn = setup();
        let state = VaultState::new();
        state.set_dek(DEK).unwrap();
        // Recovery Key + perguntas (Shamir) configuradas ANTES.
        let recovery_key =
            recovery_key::generate_recovery_key_core_for_test(&conn, "senha-mestra-xyz", DEK);
        for (q, a) in [("p1", "r1"), ("p2", "r2"), ("p3", "r3")] {
            security_questions::add_question_core(
                &conn,
                &state,
                &pw("senha-mestra-xyz"),
                q,
                &pw(a),
                &fast_params(),
            )
            .unwrap();
        }
        // Trocar, desativar e reativar a segunda senha não invalida nada disso.
        set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-nova-2"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        disable_recovery_password_core(&conn, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert_eq!(
            recovery_key::unlock_with_recovery_key_for_test(&conn, &recovery_key),
            Ok(DEK)
        );
        assert_eq!(
            security_questions::recover_with_answers_for_test(
                &conn,
                &[(1, "r1"), (2, "r2"), (3, "r3")]
            ),
            Some(DEK)
        );
        set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-abc-1"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        // E o inverso: mexer na Recovery Key/perguntas não invalida a segunda senha.
        recovery_key::generate_recovery_key_core_for_test(&conn, "senha-mestra-xyz", DEK);
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Ok(DEK)
        );
    }

    #[test]
    fn progressive_lockout_applies_to_second_password_attempts_when_enabled() {
        let conn = setup();
        lockout::set_enabled(&conn, true).unwrap();
        let clock = TestClock(Cell::new(1_000));
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("errada-123456"), &clock),
            Err(MSG_WRONG.to_string())
        );
        let locked = unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &clock)
            .unwrap_err();
        assert_eq!(locked, "E_LOCKED:15:1");
        clock.0.set(1_000 + 15_000);
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &clock),
            Ok(DEK)
        );
        // Falhas de configuração/corrupção não contam.
        conn.execute("UPDATE vault_meta SET recovery_pw_kdf_params = 'x'", [])
            .unwrap();
        for _ in 0..4 {
            assert_eq!(
                unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &clock),
                Err(MSG_CORRUPT.to_string())
            );
        }
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_RECOVERY_PASSWORD, &clock)
                .unwrap()
                .failed_count,
            0
        );
    }

    #[test]
    fn failure_while_writing_the_envelope_keeps_the_previous_state() {
        let conn = setup();
        let before: Vec<u8> = conn
            .query_row("SELECT recovery_pw_wrapped_dek FROM vault_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        conn.execute_batch("CREATE TRIGGER boom BEFORE UPDATE ON vault_meta BEGIN SELECT RAISE(ABORT, 'falha simulada'); END;").unwrap();
        assert!(set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            None,
            &pw("recuperacao-nova-2"),
            &fast_params(),
            &SystemClock
        )
        .is_err());
        conn.execute_batch("DROP TRIGGER boom").unwrap();
        let after: Vec<u8> = conn
            .query_row("SELECT recovery_pw_wrapped_dek FROM vault_meta", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            unlock_with_recovery_password_core(&conn, &pw("recuperacao-abc-1"), &SystemClock),
            Ok(DEK)
        );
    }

    #[test]
    fn plaintext_password_is_never_stored() {
        let conn = setup();
        let dump: String = conn
            .query_row(
                "SELECT hex(recovery_pw_salt) || recovery_pw_kdf_params || hex(recovery_pw_wrapped_dek) || recovery_pw_created_at FROM vault_meta",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let hex_of = |s: &str| s.bytes().map(|b| format!("{b:02X}")).collect::<String>();
        assert!(
            !dump.contains("recuperacao-abc-1") && !dump.contains(&hex_of("recuperacao-abc-1"))
        );
    }
}
