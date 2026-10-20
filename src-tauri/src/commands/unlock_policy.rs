//! Política de desbloqueio e de bloqueio progressivo: comandos de configuração e o status público
//! usado pela tela de desbloqueio.
//!
//! Tudo que ALTERA política exige o cofre desbloqueado e reautentica as credenciais atuais dentro do
//! próprio comando (nunca um flag vindo da WebView). A exigência de duas senhas é aplicada no
//! backend (`auth::authenticate`), não na interface.

use crate::auth;
use crate::commands::vault::opt_secret;
use crate::crypto::KdfParams;
use crate::db;
use crate::lockout::{self, Clock, SystemClock};
use crate::state::VaultState;
use rusqlite::Connection;
use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

const MSG_LOCKED_VAULT: &str = "O cofre está bloqueado.";

/// Foto para a interface. Nada aqui é segredo: política (uma/duas senhas), se o bloqueio
/// progressivo está ligado, o tempo restante e se outra instância mantém um cofre aberto.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct UnlockGateStatus {
    pub initialized: bool,
    pub unlocked: bool,
    /// `true` se o desbloqueio exige duas senhas.
    pub dual: bool,
    pub throttle_enabled: bool,
    pub locked: bool,
    pub remaining_seconds: i64,
    pub failed_count: i64,
    pub open_elsewhere: bool,
    pub recovery_password_enabled: bool,
    /// Há metadados de proteção ilegíveis/de versão desconhecida (a tela avisa, sem culpar a senha).
    pub protection_corrupt: bool,
}

pub fn gate_status_core(
    conn: &Connection,
    unlocked: bool,
    open_elsewhere: bool,
    clock: &dyn Clock,
) -> Result<UnlockGateStatus, String> {
    let initialized: bool = conn
        .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|e| e.to_string())?
        > 0;
    if !initialized {
        return Ok(UnlockGateStatus {
            initialized,
            unlocked,
            dual: false,
            throttle_enabled: false,
            locked: false,
            remaining_seconds: 0,
            failed_count: 0,
            open_elsewhere,
            recovery_password_enabled: false,
            protection_corrupt: false,
        });
    }
    let (dual, protection_corrupt) = match auth::read_policy(conn) {
        Ok(policy) => (policy == auth::UnlockPolicy::Dual, false),
        Err(auth::AuthError::Corrupt) => (false, true),
        Err(e) => return Err(e.to_ipc()),
    };
    let throttle = lockout::status(conn, lockout::SCOPE_UNLOCK, clock)?;
    let recovery_password_enabled = crate::commands::recovery_password::status_core(conn)
        .map(|s| s.enabled)
        .unwrap_or(false);
    Ok(UnlockGateStatus {
        initialized,
        unlocked,
        dual,
        throttle_enabled: throttle.enabled,
        locked: throttle.remaining_ms > 0,
        remaining_seconds: (throttle.remaining_ms + 999) / 1000,
        failed_count: throttle.failed_count,
        open_elsewhere,
        recovery_password_enabled,
        protection_corrupt,
    })
}

#[tauri::command]
pub fn unlock_gate_status(
    app: AppHandle,
    state: State<VaultState>,
) -> Result<UnlockGateStatus, String> {
    let conn = db::open(&app)?;
    gate_status_core(
        &conn,
        state.is_unlocked(),
        state.is_open_elsewhere(),
        &SystemClock,
    )
}

fn require_unlocked(state: &VaultState) -> Result<(), String> {
    if state.is_unlocked() {
        Ok(())
    } else {
        Err(MSG_LOCKED_VAULT.to_string())
    }
}

/// Ativa o desbloqueio com duas senhas. A senha mestra atual vira a senha 1.
#[tauri::command]
pub fn enable_dual_unlock(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    second_password: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let current_password = Zeroizing::new(current_password);
    let second_password = Zeroizing::new(second_password);
    let conn = db::open(&app)?;
    auth::enable_dual(
        &conn,
        &current_password,
        &second_password,
        &KdfParams::default(),
        &KdfParams::default(),
        &SystemClock,
    )
}

/// Desativa: volta ao desbloqueio com uma senha (a senha 1 continua sendo a senha mestra).
#[tauri::command]
pub fn disable_dual_unlock(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    current_password2: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let current_password = Zeroizing::new(current_password);
    let current_password2 = Zeroizing::new(current_password2);
    let conn = db::open(&app)?;
    auth::disable_dual(
        &conn,
        &current_password,
        &current_password2,
        &KdfParams::default(),
        &SystemClock,
    )
}

/// Troca a segunda senha de desbloqueio (a primeira permanece).
#[tauri::command]
pub fn change_second_unlock_password(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    current_password2: String,
    new_second_password: String,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let current_password = Zeroizing::new(current_password);
    let current_password2 = Zeroizing::new(current_password2);
    let new_second_password = Zeroizing::new(new_second_password);
    let conn = db::open(&app)?;
    auth::change_second(
        &conn,
        &current_password,
        &current_password2,
        &new_second_password,
        &KdfParams::default(),
        &KdfParams::default(),
        &SystemClock,
    )
}

pub fn set_throttle_core(
    conn: &Connection,
    enabled: bool,
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
    lockout::set_enabled(conn, enabled)
}

/// Liga/desliga o bloqueio progressivo por tentativas incorretas (desligado por padrão).
#[tauri::command]
pub fn set_unlock_throttle(
    app: AppHandle,
    state: State<VaultState>,
    enabled: bool,
    current_password: String,
    current_password2: Option<String>,
) -> Result<(), String> {
    require_unlocked(&state)?;
    let current_password = Zeroizing::new(current_password);
    let current_password2 = opt_secret(current_password2);
    let conn = db::open(&app)?;
    set_throttle_core(
        &conn,
        enabled,
        &current_password,
        current_password2.as_ref(),
        &SystemClock,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{fast_params, legacy_vault, TestClock};
    use crate::commands::vault::unlock_vault_with;
    use std::cell::Cell;

    const DEK: [u8; 32] = [33u8; 32];

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    fn status(conn: &Connection, clock: &dyn Clock) -> UnlockGateStatus {
        gate_status_core(conn, false, false, clock).unwrap()
    }

    #[test]
    fn legacy_vault_defaults_to_single_password_without_throttle() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        let st = status(&conn, &SystemClock);
        assert!(
            st.initialized
                && !st.dual
                && !st.throttle_enabled
                && !st.locked
                && !st.recovery_password_enabled
        );
        assert!(!st.protection_corrupt);
    }

    #[test]
    fn status_of_an_uninitialized_vault_is_neutral() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        let st = status(&conn, &SystemClock);
        assert!(!st.initialized && !st.dual && !st.locked);
    }

    #[test]
    fn status_reports_dual_throttle_and_remaining_wait() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        auth::enable_dual(
            &conn,
            "senha-mestra-xyz",
            "segunda-senha-abc",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        set_throttle_core(
            &conn,
            true,
            &pw("senha-mestra-xyz"),
            Some(&pw("segunda-senha-abc")),
            &SystemClock,
        )
        .unwrap();
        let clock = TestClock(Cell::new(10_000));
        let _ = auth::authenticate(&conn, "errada-123456", Some("segunda-senha-abc"), &clock);
        let st = status(&conn, &clock);
        assert!(st.dual && st.throttle_enabled && st.locked);
        assert_eq!((st.remaining_seconds, st.failed_count), (15, 1));
        clock.0.set(10_000 + 6_000);
        assert_eq!(status(&conn, &clock).remaining_seconds, 9);
    }

    #[test]
    fn corrupted_policy_is_flagged_instead_of_pretending_to_be_a_wrong_password() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        conn.execute("UPDATE vault_meta SET unlock_policy = 'dual-v9'", [])
            .unwrap();
        assert!(status(&conn, &SystemClock).protection_corrupt);
    }

    #[test]
    fn enabling_throttle_requires_reauthentication_and_is_off_by_default() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        assert!(set_throttle_core(&conn, true, &pw("errada-123456"), None, &SystemClock).is_err());
        assert!(!status(&conn, &SystemClock).throttle_enabled);
        set_throttle_core(&conn, true, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert!(status(&conn, &SystemClock).throttle_enabled);
        set_throttle_core(&conn, false, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert!(!status(&conn, &SystemClock).throttle_enabled);
    }

    // ---- ciclo completo através do desbloqueio real (reserva de exclusividade + auth + sessão) ----

    #[test]
    fn full_cycle_unlock_lock_recover_and_reopen_with_two_passwords() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        auth::enable_dual(
            &conn,
            "senha-mestra-xyz",
            "segunda-senha-abc",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        crate::commands::recovery_password::set_recovery_password_core(
            &conn,
            &pw("senha-mestra-xyz"),
            Some(&pw("segunda-senha-abc")),
            &pw("recuperacao-abc-1"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();

        let state = VaultState::new();
        // Uma senha só, ou a ordem errada, nunca abre.
        assert_eq!(
            unlock_vault_with(&conn, &state, &pw("senha-mestra-xyz"), None, &SystemClock),
            Err("E_SECOND_PASSWORD_REQUIRED".to_string())
        );
        assert!(unlock_vault_with(
            &conn,
            &state,
            &pw("segunda-senha-abc"),
            Some(&pw("senha-mestra-xyz")),
            &SystemClock
        )
        .is_err());
        assert!(!state.is_unlocked());
        // As duas certas abrem, e a DEK é a mesma de sempre.
        unlock_vault_with(
            &conn,
            &state,
            &pw("senha-mestra-xyz"),
            Some(&pw("segunda-senha-abc")),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(state.with_dek(|d| *d), Some(DEK));
        // "Reiniciar o app" = estado novo + a mesma conexão/arquivo: o requisito continua valendo.
        state.clear();
        let restarted = VaultState::new();
        assert!(unlock_vault_with(
            &conn,
            &restarted,
            &pw("senha-mestra-xyz"),
            None,
            &SystemClock
        )
        .is_err());
        unlock_vault_with(
            &conn,
            &restarted,
            &pw("senha-mestra-xyz"),
            Some(&pw("segunda-senha-abc")),
            &SystemClock,
        )
        .unwrap();
        // Recuperação independente quando as duas senhas foram esquecidas.
        restarted.clear();
        crate::commands::recovery_password::unlock_with_recovery_password_into_state(
            &conn,
            &restarted,
            &pw("recuperacao-abc-1"),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(restarted.with_dek(|d| *d), Some(DEK));
    }

    #[test]
    fn throttle_blocks_the_real_unlock_flow_until_the_wait_passes() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        set_throttle_core(&conn, true, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        let state = VaultState::new();
        let clock = TestClock(Cell::new(500_000));

        assert_eq!(
            unlock_vault_with(&conn, &state, &pw("errada-123456"), None, &clock),
            Err("Senha incorreta.".to_string())
        );
        assert_eq!(
            unlock_vault_with(&conn, &state, &pw("senha-mestra-xyz"), None, &clock),
            Err("E_LOCKED:15:1".to_string())
        );
        assert!(
            !state.is_unlocked(),
            "durante o bloqueio nem a senha certa abre"
        );
        clock.0.set(500_000 + 15_000);
        assert_eq!(
            unlock_vault_with(&conn, &state, &pw("errada-123456"), None, &clock),
            Err("Senha incorreta.".to_string())
        );
        assert_eq!(
            unlock_vault_with(&conn, &state, &pw("senha-mestra-xyz"), None, &clock),
            Err("E_LOCKED:30:2".to_string())
        );
        clock.0.set(500_000 + 15_000 + 30_000);
        unlock_vault_with(&conn, &state, &pw("senha-mestra-xyz"), None, &clock).unwrap();
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_UNLOCK, &clock)
                .unwrap()
                .failed_count,
            0
        );
    }

    #[test]
    fn credential_changes_keep_every_other_recovery_method_valid() {
        let conn = legacy_vault("senha-mestra-xyz", DEK);
        let state = VaultState::new();
        state.set_dek(DEK).unwrap();
        let recovery_key = crate::commands::recovery_key::generate_recovery_key_core_for_test(
            &conn,
            "senha-mestra-xyz",
            DEK,
        );
        crate::commands::security_questions::add_question_core(
            &conn,
            &state,
            &pw("senha-mestra-xyz"),
            "p1",
            &pw("r1"),
            &fast_params(),
        )
        .unwrap();
        crate::commands::security_questions::add_question_core(
            &conn,
            &state,
            &pw("senha-mestra-xyz"),
            "p2",
            &pw("r2"),
            &fast_params(),
        )
        .unwrap();
        crate::commands::security_questions::add_question_core(
            &conn,
            &state,
            &pw("senha-mestra-xyz"),
            "p3",
            &pw("r3"),
            &fast_params(),
        )
        .unwrap();

        auth::enable_dual(
            &conn,
            "senha-mestra-xyz",
            "segunda-senha-abc",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        crate::commands::vault::change_master_password_core(
            &conn,
            &state,
            &pw("senha-mestra-xyz"),
            Some(&pw("segunda-senha-abc")),
            &pw("senha-mestra-nova"),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        auth::disable_dual(
            &conn,
            "senha-mestra-nova",
            "segunda-senha-abc",
            &fast_params(),
            &SystemClock,
        )
        .unwrap();

        assert_eq!(
            crate::commands::recovery_key::unlock_with_recovery_key_for_test(&conn, &recovery_key),
            Ok(DEK)
        );
        assert_eq!(
            crate::commands::security_questions::recover_with_answers_for_test(
                &conn,
                &[(1, "r1"), (2, "r2"), (3, "r3")]
            ),
            Some(DEK)
        );
    }
}

#[cfg(test)]
mod exclusivity_tests {
    use super::*;
    use crate::auth::tests::legacy_vault;
    use crate::commands::vault::unlock_vault_with;

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    fn instance(path: &std::path::Path) -> VaultState {
        let state = VaultState::with_exclusive_lock();
        state.set_exclusive_path(path.to_path_buf());
        state
    }

    #[test]
    fn a_second_instance_is_told_a_vault_is_already_open_without_spending_password_attempts() {
        let dir = std::env::temp_dir().join(format!("cofre-excl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault-unlocked.lock");
        let conn = legacy_vault("senha-mestra-xyz", [44u8; 32]);
        set_throttle_core(&conn, true, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();

        let first = instance(&path);
        let second = instance(&path);
        unlock_vault_with(&conn, &first, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();

        // Segunda instância: nem a senha certa nem a errada passam; e NADA é cobrado do bloqueio.
        for attempt in ["senha-mestra-xyz", "errada-123456"] {
            assert_eq!(
                unlock_vault_with(&conn, &second, &pw(attempt), None, &SystemClock),
                Err("E_VAULT_OPEN_ELSEWHERE".to_string())
            );
        }
        assert!(!second.is_unlocked());
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_UNLOCK, &SystemClock)
                .unwrap()
                .failed_count,
            0
        );
        let gate = gate_status_core(
            &conn,
            second.is_unlocked(),
            second.is_open_elsewhere(),
            &SystemClock,
        )
        .unwrap();
        assert!(
            gate.open_elsewhere,
            "a tela de desbloqueio informa que já existe um cofre aberto"
        );

        // Recuperação também respeita a exclusividade.
        let rk = crate::commands::recovery_key::generate_recovery_key_core_for_test(
            &conn,
            "senha-mestra-xyz",
            [44u8; 32],
        );
        assert_eq!(
            crate::commands::recovery_key::unlock_with_recovery_key_into_state(
                &conn,
                &second,
                &pw(&rk)
            ),
            Err("E_VAULT_OPEN_ELSEWHERE".to_string())
        );

        first.clear();
        unlock_vault_with(&conn, &second, &pw("senha-mestra-xyz"), None, &SystemClock).unwrap();
        assert_eq!(second.with_dek(|d| *d), Some([44u8; 32]));
        drop((first, second));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
