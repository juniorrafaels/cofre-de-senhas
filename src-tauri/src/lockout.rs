//! Bloqueio progressivo por tentativas de autenticação incorretas.
//!
//! O estado vive no SQLite (`auth_throttle`), nunca no frontend nem em memória do processo:
//! sobrevive a reinícios e vale para todas as janelas e instâncias que compartilham o mesmo banco.
//! Cada tentativa é *cobrada antes* de a senha ser verificada, dentro de uma transação
//! `BEGIN IMMEDIATE` (escritor único): duas instâncias disparando tentativas ao mesmo tempo não
//! conseguem "furar" o contador — a segunda enxerga o bloqueio criado pela primeira. Se a senha
//! estava correta, a cobrança é zerada; se a falha foi interna (não é um erro de senha), a
//! cobrança é devolvida (`Ticket::refund`).
//!
//! Relógio: usa o relógio de parede (epoch em ms) porque o prazo precisa sobreviver a reinícios,
//! suspensão e hibernação (um relógio monotônico não faz isso). Para que mexer no relógio nunca
//! gere um bloqueio permanente, o tempo restante é sempre limitado ao tempo de espera daquela
//! falha (`wait_ms`): voltar o relógio não alonga a espera além do previsto, mas também não a
//! encurta. Adiantar o relógio encurta a espera — limitação documentada em `SECURITY.md`; quem
//! controla os arquivos locais ou o relógio do sistema pode contornar esta política.
//!
//! Estado corrompido (tipos inválidos, valores fora de faixa) falha FECHADO, porém de forma
//! limitada: vira o bloqueio máximo (4 h) a partir de agora e é regravado, sem nunca virar
//! bloqueio permanente. Os métodos de recuperação independentes continuam disponíveis.

use rusqlite::{params, Connection, OptionalExtension};

pub const SCOPE_UNLOCK: &str = "unlock";
pub const SCOPE_RECOVERY_PASSWORD: &str = "recovery_password";

/// Teto da espera (falhas consecutivas >= 8): 4 horas.
pub const MAX_WAIT_MS: i64 = 4 * 60 * 60 * 1000;
const MAX_FAILED_COUNT: i64 = 1_000_000;
/// Contagem assumida ao regravar um estado corrompido (já no degrau máximo da tabela).
const CORRUPT_STATE_FAILED_COUNT: i64 = 8;

pub trait Clock {
    fn now_ms(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

/// Tabela de espera por número de falhas consecutivas (já incluindo a falha atual).
pub fn wait_for_failures_ms(failed_count: i64) -> i64 {
    const SEC: i64 = 1000;
    match failed_count {
        i64::MIN..=0 => 0,
        1 => 15 * SEC,
        2 => 30 * SEC,
        3 => 60 * SEC,
        4 => 5 * 60 * SEC,
        5 => 30 * 60 * SEC,
        6 => 60 * 60 * SEC,
        7 => 2 * 60 * 60 * SEC,
        _ => MAX_WAIT_MS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleState {
    pub enabled: bool,
    pub failed_count: i64,
    pub locked_until_ms: i64,
    pub wait_ms: i64,
}

impl ThrottleState {
    /// Tempo de bloqueio restante em `now_ms`, sempre dentro de `0..=wait_ms` (ver doc do módulo).
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        (self.locked_until_ms.saturating_sub(now_ms)).clamp(0, self.wait_ms.clamp(0, MAX_WAIT_MS))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ThrottleError {
    Locked {
        remaining_ms: i64,
        failed_count: i64,
    },
    Internal(String),
}

#[derive(Debug)]
enum LoadError {
    Corrupt,
    Internal(String),
}

fn load(conn: &Connection, scope: &str) -> Result<Option<ThrottleState>, LoadError> {
    let row = conn
        .query_row(
            "SELECT enabled, failed_count, locked_until_ms, wait_ms FROM auth_throttle WHERE scope = ?1",
            [scope],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)),
        )
        .optional();
    let (enabled, failed_count, locked_until_ms, wait_ms) = match row {
        Ok(Some(values)) => values,
        Ok(None) => return Ok(None),
        Err(
            rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..),
        ) => return Err(LoadError::Corrupt),
        Err(e) => return Err(LoadError::Internal(e.to_string())),
    };
    if !(enabled == 0 || enabled == 1)
        || !(0..=MAX_FAILED_COUNT).contains(&failed_count)
        || locked_until_ms < 0
        || !(0..=MAX_WAIT_MS).contains(&wait_ms)
    {
        return Err(LoadError::Corrupt);
    }
    Ok(Some(ThrottleState {
        enabled: enabled == 1,
        failed_count,
        locked_until_ms,
        wait_ms,
    }))
}

fn upsert(conn: &Connection, scope: &str, s: &ThrottleState) -> Result<(), String> {
    conn.execute(
        "INSERT INTO auth_throttle (scope, enabled, failed_count, locked_until_ms, wait_ms) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(scope) DO UPDATE SET enabled = ?2, failed_count = ?3, locked_until_ms = ?4, wait_ms = ?5",
        params![scope, s.enabled as i64, s.failed_count, s.locked_until_ms, s.wait_ms],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Estado "bloqueio máximo a partir de agora", usado para regravar um estado corrompido.
fn corrupt_fallback(now_ms: i64) -> ThrottleState {
    ThrottleState {
        enabled: true,
        failed_count: CORRUPT_STATE_FAILED_COUNT,
        locked_until_ms: now_ms.saturating_add(MAX_WAIT_MS),
        wait_ms: MAX_WAIT_MS,
    }
}

/// Foto do estado para a interface (leitura apenas, nunca escreve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleStatus {
    pub enabled: bool,
    pub failed_count: i64,
    pub remaining_ms: i64,
}

pub fn status(conn: &Connection, scope: &str, clock: &dyn Clock) -> Result<ThrottleStatus, String> {
    match load(conn, scope) {
        Ok(None) => Ok(ThrottleStatus {
            enabled: false,
            failed_count: 0,
            remaining_ms: 0,
        }),
        Ok(Some(s)) => Ok(ThrottleStatus {
            enabled: s.enabled,
            failed_count: s.failed_count,
            remaining_ms: if s.enabled {
                s.remaining_ms(clock.now_ms())
            } else {
                0
            },
        }),
        Err(LoadError::Corrupt) => Ok(ThrottleStatus {
            enabled: true,
            failed_count: CORRUPT_STATE_FAILED_COUNT,
            remaining_ms: MAX_WAIT_MS,
        }),
        Err(LoadError::Internal(e)) => Err(e),
    }
}

/// Liga ou desliga a política para os dois escopos (desbloqueio e recuperação por segunda senha).
/// Sempre zera as falhas acumuladas. Atômico.
pub fn set_enabled(conn: &Connection, enabled: bool) -> Result<(), String> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    let result = (|| {
        for scope in [SCOPE_UNLOCK, SCOPE_RECOVERY_PASSWORD] {
            upsert(
                conn,
                scope,
                &ThrottleState {
                    enabled,
                    failed_count: 0,
                    locked_until_ms: 0,
                    wait_ms: 0,
                },
            )?;
        }
        Ok::<(), String>(())
    })();
    finish_tx(conn, result)
}

fn finish_tx<T>(conn: &Connection, result: Result<T, String>) -> Result<T, String> {
    match result {
        Ok(v) => {
            if let Err(e) = conn.execute_batch("COMMIT") {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e.to_string());
            }
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Resultado de `begin`: o que fazer depois que a verificação terminar.
#[derive(Debug)]
pub enum Ticket {
    /// Política desligada (ou sem linha): nada foi cobrado, nada a desfazer.
    Inactive,
    Charged {
        scope: &'static str,
        previous: ThrottleState,
        charged: ThrottleState,
    },
}

impl Ticket {
    /// Autenticação válida: limpa a sequência de falhas.
    pub fn succeed(self, conn: &Connection) {
        if let Ticket::Charged { scope, .. } = self {
            let _ = conn.execute(
                "UPDATE auth_throttle SET failed_count = 0, locked_until_ms = 0, wait_ms = 0 WHERE scope = ?1 AND enabled = 1",
                [scope],
            );
        }
    }

    /// A verificação falhou por motivo que NÃO é senha incorreta (erro interno, dados corrompidos):
    /// devolve a cobrança, exceto se outra tentativa já alterou o estado desde então.
    pub fn refund(self, conn: &Connection) {
        if let Ticket::Charged {
            scope,
            previous,
            charged,
        } = self
        {
            let _ = conn.execute(
                "UPDATE auth_throttle SET failed_count = ?1, locked_until_ms = ?2, wait_ms = ?3 \
                 WHERE scope = ?4 AND failed_count = ?5 AND locked_until_ms = ?6",
                params![
                    previous.failed_count,
                    previous.locked_until_ms,
                    previous.wait_ms,
                    scope,
                    charged.failed_count,
                    charged.locked_until_ms
                ],
            );
        }
    }
}

/// Verifica o bloqueio e, se liberado, COBRA a tentativa (ver doc do módulo). Deve ser chamado
/// imediatamente antes de verificar a senha.
pub fn begin(
    conn: &Connection,
    scope: &'static str,
    clock: &dyn Clock,
) -> Result<Ticket, ThrottleError> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| ThrottleError::Internal(e.to_string()))?;
    let now = clock.now_ms();

    let outcome: Result<Result<Ticket, ThrottleError>, String> = (|| match load(conn, scope) {
        Ok(None) => Ok(Ok(Ticket::Inactive)),
        Ok(Some(s)) if !s.enabled => Ok(Ok(Ticket::Inactive)),
        Ok(Some(s)) => {
            let remaining = s.remaining_ms(now);
            if remaining > 0 {
                return Ok(Err(ThrottleError::Locked {
                    remaining_ms: remaining,
                    failed_count: s.failed_count,
                }));
            }
            let failed_count = s.failed_count.saturating_add(1).min(MAX_FAILED_COUNT);
            let wait_ms = wait_for_failures_ms(failed_count);
            let charged = ThrottleState {
                enabled: true,
                failed_count,
                locked_until_ms: now.saturating_add(wait_ms),
                wait_ms,
            };
            upsert(conn, scope, &charged)?;
            Ok(Ok(Ticket::Charged {
                scope,
                previous: s,
                charged,
            }))
        }
        Err(LoadError::Corrupt) => {
            let fallback = corrupt_fallback(now);
            upsert(conn, scope, &fallback)?;
            Ok(Err(ThrottleError::Locked {
                remaining_ms: MAX_WAIT_MS,
                failed_count: fallback.failed_count,
            }))
        }
        Err(LoadError::Internal(e)) => Err(e),
    })();

    // Um bloqueio ativo é um resultado normal (a transação só leu/gravou o que precisava).
    match finish_tx(conn, outcome) {
        Ok(inner) => inner,
        Err(e) => Err(ThrottleError::Internal(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeClock(Cell<i64>);
    impl FakeClock {
        fn new(ms: i64) -> Self {
            Self(Cell::new(ms))
        }
        fn advance_secs(&self, secs: i64) {
            self.0.set(self.0.get() + secs * 1000);
        }
    }
    impl Clock for FakeClock {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }

    fn conn_with_table() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_table(&conn);
        conn
    }

    fn create_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE auth_throttle (scope TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, \
             failed_count INTEGER NOT NULL DEFAULT 0, locked_until_ms INTEGER NOT NULL DEFAULT 0, wait_ms INTEGER NOT NULL DEFAULT 0);",
        )
        .unwrap();
    }

    /// Uma tentativa que termina em falha de senha (cobrança mantida).
    fn fail_once(conn: &Connection, clock: &FakeClock) -> Result<(), ThrottleError> {
        begin(conn, SCOPE_UNLOCK, clock).map(|_ticket| ())
    }

    #[test]
    fn wait_table_matches_the_documented_progression() {
        let secs = |n| wait_for_failures_ms(n) / 1000;
        assert_eq!(secs(0), 0);
        assert_eq!(secs(1), 15);
        assert_eq!(secs(2), 30);
        assert_eq!(secs(3), 60);
        assert_eq!(secs(4), 5 * 60);
        assert_eq!(secs(5), 30 * 60);
        assert_eq!(secs(6), 60 * 60);
        assert_eq!(secs(7), 2 * 60 * 60);
        assert_eq!(secs(8), 4 * 60 * 60);
        assert_eq!(secs(50), 4 * 60 * 60);
        assert_eq!(wait_for_failures_ms(i64::MAX), MAX_WAIT_MS);
    }

    #[test]
    fn disabled_by_default_never_charges_or_blocks() {
        let conn = conn_with_table();
        let clock = FakeClock::new(1_000_000);
        for _ in 0..20 {
            assert!(matches!(
                begin(&conn, SCOPE_UNLOCK, &clock),
                Ok(Ticket::Inactive)
            ));
        }
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM auth_throttle", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "política desligada não grava nada");
    }

    #[test]
    fn failures_escalate_through_the_whole_table_with_an_injected_clock() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(5_000_000);
        let expected_secs = [15, 30, 60, 300, 1800, 3600, 7200, 14400, 14400, 14400];
        for (i, expected) in expected_secs.iter().enumerate() {
            // A tentativa é aceita (não está bloqueado) e vira uma falha de senha.
            fail_once(&conn, &clock)
                .unwrap_or_else(|e| panic!("tentativa {} deveria ser permitida: {e:?}", i + 1));
            let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
            assert_eq!(st.failed_count, i as i64 + 1);
            assert_eq!(
                st.remaining_ms,
                expected * 1000,
                "espera após a falha {}",
                i + 1
            );
            // Durante o bloqueio qualquer tentativa é recusada SEM contar como nova falha.
            match fail_once(&conn, &clock) {
                Err(ThrottleError::Locked {
                    remaining_ms,
                    failed_count,
                }) => {
                    assert_eq!(remaining_ms, expected * 1000);
                    assert_eq!(failed_count, i as i64 + 1);
                }
                other => panic!("esperava bloqueio, veio {other:?}"),
            }
            assert_eq!(
                status(&conn, SCOPE_UNLOCK, &clock).unwrap().failed_count,
                i as i64 + 1
            );
            // Passado o prazo, a próxima tentativa é liberada.
            clock.advance_secs(*expected);
            assert_eq!(status(&conn, SCOPE_UNLOCK, &clock).unwrap().remaining_ms, 0);
        }
    }

    #[test]
    fn lock_expires_only_when_the_full_wait_has_elapsed() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&conn, &clock).unwrap();
        clock.advance_secs(14);
        assert!(matches!(
            fail_once(&conn, &clock),
            Err(ThrottleError::Locked { .. })
        ));
        clock.advance_secs(1);
        assert!(
            fail_once(&conn, &clock).is_ok(),
            "no instante exato do prazo a tentativa é liberada"
        );
    }

    #[test]
    fn successful_authentication_clears_the_failure_streak() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&conn, &clock).unwrap();
        clock.advance_secs(15);
        fail_once(&conn, &clock).unwrap();
        clock.advance_secs(30);
        let ticket = begin(&conn, SCOPE_UNLOCK, &clock).unwrap();
        ticket.succeed(&conn);
        let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
        assert_eq!((st.failed_count, st.remaining_ms), (0, 0));
        // A sequência recomeça do degrau 1.
        fail_once(&conn, &clock).unwrap();
        assert_eq!(
            status(&conn, SCOPE_UNLOCK, &clock).unwrap().remaining_ms,
            15_000
        );
    }

    #[test]
    fn non_password_failures_are_refunded() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&conn, &clock).unwrap(); // 1 falha real
        clock.advance_secs(15);
        let ticket = begin(&conn, SCOPE_UNLOCK, &clock).unwrap(); // cobra a 2ª
        assert_eq!(status(&conn, SCOPE_UNLOCK, &clock).unwrap().failed_count, 2);
        ticket.refund(&conn); // erro interno: devolve
        let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
        assert_eq!(st.failed_count, 1);
        // O prazo anterior (já vencido) é o que vale; a tentativa seguinte é liberada.
        assert_eq!(st.remaining_ms, 0);
        assert!(fail_once(&conn, &clock).is_ok());
    }

    #[test]
    fn refund_does_not_overwrite_a_newer_state() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        let ticket = begin(&conn, SCOPE_UNLOCK, &clock).unwrap(); // falha 1 cobrada
                                                                  // Outra instância já avançou o estado (falha 2) antes de o reembolso chegar.
        conn.execute(
            "UPDATE auth_throttle SET failed_count = 2 WHERE scope = 'unlock'",
            [],
        )
        .unwrap();
        ticket.refund(&conn);
        assert_eq!(status(&conn, SCOPE_UNLOCK, &clock).unwrap().failed_count, 2);
    }

    #[test]
    fn state_persists_across_connections_like_an_app_restart() {
        let dir = std::env::temp_dir().join(format!("cofre-lockout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("restart.db");
        let _ = std::fs::remove_file(&path);
        let clock = FakeClock::new(10_000);
        {
            let conn = Connection::open(&path).unwrap();
            create_table(&conn);
            set_enabled(&conn, true).unwrap();
            fail_once(&conn, &clock).unwrap();
            fail_once(&conn, &clock).unwrap_err();
        } // "fecha o app"
        {
            let conn = Connection::open(&path).unwrap(); // "reabre o app"
            let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
            assert_eq!(
                (st.enabled, st.failed_count, st.remaining_ms),
                (true, 1, 15_000)
            );
            assert!(matches!(
                begin(&conn, SCOPE_UNLOCK, &clock),
                Err(ThrottleError::Locked { .. })
            ));
            clock.advance_secs(15);
            assert!(begin(&conn, SCOPE_UNLOCK, &clock).is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_connections_share_the_same_lock_like_two_app_instances() {
        let dir = std::env::temp_dir().join(format!("cofre-lockout-two-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("shared.db");
        let _ = std::fs::remove_file(&path);
        let a = Connection::open(&path).unwrap();
        create_table(&a);
        set_enabled(&a, true).unwrap();
        let b = Connection::open(&path).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&a, &clock).unwrap();
        assert!(
            matches!(fail_once(&b, &clock), Err(ThrottleError::Locked { .. })),
            "a outra instância enxerga o bloqueio"
        );
        drop((a, b));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rolling_the_clock_back_never_extends_the_wait_beyond_its_length() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(1_000_000_000_000);
        fail_once(&conn, &clock).unwrap(); // espera de 15 s
        clock.0.set(0); // relógio voltou ~31 anos
        let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
        assert_eq!(
            st.remaining_ms, 15_000,
            "no máximo a espera original, nunca um bloqueio gigante"
        );
    }

    #[test]
    fn corrupted_state_fails_closed_but_bounded_and_is_rewritten() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(7_000);
        for bad in [
            "UPDATE auth_throttle SET failed_count = 'lixo' WHERE scope = 'unlock'",
            "UPDATE auth_throttle SET wait_ms = -5 WHERE scope = 'unlock'",
            "UPDATE auth_throttle SET wait_ms = 999999999999 WHERE scope = 'unlock'",
            "UPDATE auth_throttle SET enabled = 7 WHERE scope = 'unlock'",
            "UPDATE auth_throttle SET failed_count = -1 WHERE scope = 'unlock'",
        ] {
            set_enabled(&conn, true).unwrap();
            conn.execute(bad, []).unwrap();
            match begin(&conn, SCOPE_UNLOCK, &clock) {
                Err(ThrottleError::Locked { remaining_ms, .. }) => {
                    assert_eq!(remaining_ms, MAX_WAIT_MS, "{bad}")
                }
                other => panic!("{bad}: esperava bloqueio máximo, veio {other:?}"),
            }
            // Regravado em estado válido e LIMITADO: expira sozinho depois de 4 h.
            let st = status(&conn, SCOPE_UNLOCK, &clock).unwrap();
            assert_eq!(st.remaining_ms, MAX_WAIT_MS);
            clock.advance_secs(4 * 3600);
            assert_eq!(
                status(&conn, SCOPE_UNLOCK, &clock).unwrap().remaining_ms,
                0,
                "{bad}: nunca permanente"
            );
            clock.advance_secs(-4 * 3600);
        }
    }

    #[test]
    fn missing_table_is_an_internal_error_not_a_password_error() {
        let conn = Connection::open_in_memory().unwrap();
        let clock = FakeClock::new(0);
        assert!(matches!(
            begin(&conn, SCOPE_UNLOCK, &clock),
            Err(ThrottleError::Internal(_))
        ));
    }

    #[test]
    fn scopes_are_independent() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&conn, &clock).unwrap();
        assert!(
            begin(&conn, SCOPE_RECOVERY_PASSWORD, &clock).is_ok(),
            "bloquear o desbloqueio não bloqueia a recuperação"
        );
    }

    #[test]
    fn disabling_resets_the_streak() {
        let conn = conn_with_table();
        set_enabled(&conn, true).unwrap();
        let clock = FakeClock::new(0);
        fail_once(&conn, &clock).unwrap();
        set_enabled(&conn, false).unwrap();
        assert!(matches!(
            begin(&conn, SCOPE_UNLOCK, &clock),
            Ok(Ticket::Inactive)
        ));
        set_enabled(&conn, true).unwrap();
        assert_eq!(status(&conn, SCOPE_UNLOCK, &clock).unwrap().failed_count, 0);
    }
}
