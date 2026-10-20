use crate::instance_lock::{InstanceLock, LockError};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Código estável devolvido à interface quando outra instância já mantém um cofre desbloqueado.
pub const ERR_VAULT_OPEN_ELSEWHERE: &str = "E_VAULT_OPEN_ELSEWHERE";
const LOCK_ATTEMPTS: u32 = 3;
const LOCK_RETRY_PAUSE: Duration = Duration::from_millis(25);
const ERR_EXCLUSIVITY_UNAVAILABLE: &str = "Não foi possível garantir a exclusividade do cofre aberto (arquivo de controle indisponível).";

/// Limita a taxa de chamadas a operações de "revelar" (que devolvem o segredo em texto puro ao
/// JS, sob clique explícito do usuário) — não para impedir um XSS determinado (que pode esperar
/// a janela liberar e continuar), mas para transformar um dump automatizado instantâneo de todas
/// as contas em algo que leva bem mais tempo, dando uma chance real de o usuário notar algo
/// estranho ou bloquear o cofre no meio do caminho (ver SECURITY_AUDIT_PHASE_4.md, seção
/// "Reautenticação e rate limiting" para a justificativa completa e as limitações honestas disso).
/// Não é aplicado a `copy_*` (copiar não devolve nada ao JS) nem a leituras de metadados como
/// notes/2FA (abertas automaticamente ao visualizar uma conta — penalizar isso quebraria a UX).
pub struct RevealLimiter {
    window: Duration,
    max_calls: usize,
    calls: Mutex<VecDeque<Instant>>,
}

impl RevealLimiter {
    fn new(window: Duration, max_calls: usize) -> Self {
        Self { window, max_calls, calls: Mutex::new(VecDeque::new()) }
    }

    /// Registra uma nova tentativa e rejeita se já houve `max_calls` dentro da janela deslizante.
    /// Nunca bloqueia permanentemente: entradas mais antigas que a janela são descartadas a cada
    /// chamada, então o limite se libera sozinho com o tempo, sem precisar de um "reset" manual.
    pub fn check_and_record(&self) -> Result<(), String> {
        let now = Instant::now();
        let mut calls = self.calls.lock().unwrap();
        while let Some(&oldest) = calls.front() {
            if now.duration_since(oldest) > self.window {
                calls.pop_front();
            } else {
                break;
            }
        }
        if calls.len() >= self.max_calls {
            return Err("Muitas revelações em pouco tempo. Aguarde alguns segundos e tente novamente.".to_string());
        }
        calls.push_back(now);
        Ok(())
    }
}

/// Como a DEK atualmente em memória foi obtida. Só importa para uma decisão: redefinir a senha
/// mestra SEM informar a atual (`reset_master_password_after_recovery`) é permitido apenas numa
/// sessão aberta por um mecanismo de recuperação (Recovery Key ou perguntas de segurança). Uma
/// sessão aberta normalmente pela senha mestra precisa passar por `change_master_password`, que
/// reautentica a senha atual — senão qualquer código rodando na WebView de uma sessão comum
/// (ex.: XSS) conseguiria trocar a senha mestra sem conhecê-la.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockMethod {
    MasterPassword,
    Recovery,
}

struct Session {
    dek: Zeroizing<[u8; 32]>,
    method: UnlockMethod,
    /// Lock exclusivo de "cofre aberto" (ver `instance_lock`). Vive e morre com a sessão: bloquear
    /// o cofre, o auto-lock ou o fim do processo soltam o lock. `None` só com a exclusividade
    /// desligada (testes).
    _exclusive: Option<InstanceLock>,
}

/// Como a exclusividade de cofre aberto é obtida por este `VaultState`.
enum ExclusiveMode {
    /// Sem coordenação entre processos (testes unitários).
    Disabled,
    /// App real, mas o caminho do arquivo de controle ainda não foi definido: falha FECHADO.
    Pending,
    Path(PathBuf),
}

/// Reserva de exclusividade obtida ANTES de verificar credenciais (assim uma segunda instância
/// nunca gasta tentativas de senha nem revela se a senha está certa). Soltar sem usar libera.
pub struct Reservation(Option<InstanceLock>);

pub struct VaultState {
    // DEK e método de desbloqueio ficam sob o MESMO mutex para que nunca exista uma janela em que
    // a DEK de uma sessão normal conviva com o flag de recuperação de uma sessão anterior.
    session: Mutex<Option<Session>>,
    exclusive: Mutex<ExclusiveMode>,
    pub reveal_limiter: RevealLimiter,
}

impl VaultState {
    /// Sem exclusividade entre processos — usado por testes unitários.
    pub fn new() -> Self {
        Self {
            session: Mutex::new(None),
            exclusive: Mutex::new(ExclusiveMode::Disabled),
            reveal_limiter: RevealLimiter::new(Duration::from_secs(10), 25),
        }
    }

    /// App real: exige o lock exclusivo; enquanto `set_exclusive_path` não for chamado, nenhum
    /// desbloqueio é permitido (nunca abre sem a garantia).
    pub fn with_exclusive_lock() -> Self {
        let state = Self::new();
        *state.exclusive.lock().unwrap() = ExclusiveMode::Pending;
        state
    }

    pub fn set_exclusive_path(&self, path: PathBuf) {
        *self.exclusive.lock().unwrap() = ExclusiveMode::Path(path);
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.lock().unwrap().is_some()
    }

    fn acquire_lock(&self) -> Result<Option<InstanceLock>, String> {
        match &*self.exclusive.lock().unwrap() {
            ExclusiveMode::Disabled => Ok(None),
            ExclusiveMode::Pending => Err(ERR_EXCLUSIVITY_UNAVAILABLE.to_string()),
            ExclusiveMode::Path(path) => {
                // Pequenas tentativas extras: outra instância pode estar só SONDANDO o lock (a tela
                // de desbloqueio consulta "há cofre aberto em outro lugar?") e soltá-lo em
                // microssegundos. Um dono real mantém o lock indefinidamente, então o resultado
                // final é o mesmo — só evita um falso "já existe um cofre aberto".
                for attempt in 0..LOCK_ATTEMPTS {
                    match InstanceLock::try_acquire(path) {
                        Ok(lock) => return Ok(Some(lock)),
                        Err(LockError::Busy) if attempt + 1 < LOCK_ATTEMPTS => std::thread::sleep(LOCK_RETRY_PAUSE),
                        Err(LockError::Busy) => return Err(ERR_VAULT_OPEN_ELSEWHERE.to_string()),
                        Err(LockError::Io(e)) => {
                            eprintln!("[instance_lock] não foi possível usar o arquivo de controle: {e}");
                            return Err(ERR_EXCLUSIVITY_UNAVAILABLE.to_string());
                        }
                    }
                }
                Err(ERR_VAULT_OPEN_ELSEWHERE.to_string())
            }
        }
    }

    /// Reserva a exclusividade. Se esta própria sessão já a detém (ex.: nova verificação com o
    /// cofre desbloqueado), não adquire outra — um segundo handle no mesmo processo conflitaria.
    pub fn reserve_exclusive(&self) -> Result<Reservation, String> {
        if self.session.lock().unwrap().is_some() {
            return Ok(Reservation(None));
        }
        self.acquire_lock().map(Reservation)
    }

    /// `true` se OUTRA instância mantém um cofre desbloqueado (sonda rápida; solta em seguida).
    pub fn is_open_elsewhere(&self) -> bool {
        if self.session.lock().unwrap().is_some() {
            return false;
        }
        matches!(self.acquire_lock(), Err(e) if e == ERR_VAULT_OPEN_ELSEWHERE)
    }

    /// Abre a sessão. Sem reserva própria, reaproveita o lock da sessão atual; se não houver
    /// sessão, tenta adquirir agora (nunca existe sessão sem a exclusividade).
    pub fn commit(&self, dek: [u8; 32], method: UnlockMethod, reservation: Reservation) -> Result<(), String> {
        let mut guard = self.session.lock().unwrap();
        let lock = match reservation.0 {
            Some(lock) => Some(lock),
            None => match guard.as_mut().and_then(|s| s._exclusive.take()) {
                Some(lock) => Some(lock),
                None if guard.is_some() => None, // sessão sem lock só existe com a exclusividade desligada
                None => self.acquire_lock()?,
            },
        };
        *guard = Some(Session { dek: Zeroizing::new(dek), method, _exclusive: lock });
        Ok(())
    }

    /// Desbloqueio normal (senha mestra / criação do cofre / troca de senha reautenticada).
    /// Sempre zera o flag de recuperação.
    pub fn set_dek(&self, dek: [u8; 32]) -> Result<(), String> {
        self.commit(dek, UnlockMethod::MasterPassword, Reservation(None))
    }

    /// Desbloqueio por um mecanismo de recuperação bem-sucedido (Recovery Key, perguntas de
    /// segurança ou segunda senha de recuperação). Só estes caminhos podem chamar isto.
    #[cfg(test)]
    pub fn set_dek_from_recovery(&self, dek: [u8; 32]) -> Result<(), String> {
        self.commit(dek, UnlockMethod::Recovery, Reservation(None))
    }

    pub fn clear(&self) {
        *self.session.lock().unwrap() = None;
    }

    #[cfg(test)]
    pub fn unlock_method(&self) -> Option<UnlockMethod> {
        self.session.lock().unwrap().as_ref().map(|s| s.method)
    }

    pub fn with_dek<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> Option<T> {
        self.session.lock().unwrap().as_ref().map(|s| f(&s.dek))
    }

    /// Como `with_dek`, mas só executa `f` se a sessão atual foi aberta por recuperação.
    pub fn with_recovery_dek<T>(&self, f: impl FnOnce(&[u8; 32]) -> T) -> Option<T> {
        self.session
            .lock()
            .unwrap()
            .as_ref()
            .filter(|s| s.method == UnlockMethod::Recovery)
            .map(|s| f(&s.dek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_limiter_blocks_after_threshold_and_recovers() {
        let limiter = RevealLimiter::new(Duration::from_millis(50), 3);
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_ok());
        assert!(limiter.check_and_record().is_err(), "a 4a chamada dentro da janela deveria ser bloqueada");

        std::thread::sleep(Duration::from_millis(60));
        assert!(limiter.check_and_record().is_ok(), "depois da janela expirar, deveria liberar de novo");
    }

    fn temp_lock_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cofre-state-lock-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault-unlocked.lock")
    }

    fn instance_at(path: &std::path::Path) -> VaultState {
        let state = VaultState::with_exclusive_lock();
        state.set_exclusive_path(path.to_path_buf());
        state
    }

    #[test]
    fn a_second_instance_cannot_unlock_while_the_first_is_open_and_can_after_it_locks() {
        let path = temp_lock_path("two-instances");
        let first = instance_at(&path);
        let second = instance_at(&path);

        first.set_dek([1u8; 32]).unwrap();
        assert!(second.is_open_elsewhere(), "a UI consegue avisar que já existe um cofre aberto");
        assert!(!first.is_open_elsewhere());
        assert_eq!(second.set_dek([2u8; 32]), Err(ERR_VAULT_OPEN_ELSEWHERE.to_string()));
        assert!(second.reserve_exclusive().is_err());
        assert!(!second.is_unlocked(), "a segunda instância não fica com sessão nenhuma");

        first.clear(); // bloqueio manual libera o controle
        assert!(!second.is_open_elsewhere());
        second.set_dek([2u8; 32]).unwrap();
        assert!(first.reserve_exclusive().is_err(), "agora é a primeira que não pode abrir outro");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unlocking_again_inside_the_same_instance_keeps_the_exclusive_control() {
        let path = temp_lock_path("same-instance");
        let state = instance_at(&path);
        state.set_dek([1u8; 32]).unwrap();
        state.set_dek([1u8; 32]).unwrap(); // troca de senha / nova verificação com o cofre aberto
        state.set_dek_from_recovery([1u8; 32]).unwrap();
        assert!(instance_at(&path).is_open_elsewhere(), "o controle não foi perdido na reabertura");
        state.clear();
        assert!(!instance_at(&path).is_open_elsewhere());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn exclusivity_fails_closed_until_the_lock_path_is_configured() {
        let state = VaultState::with_exclusive_lock();
        assert!(state.set_dek([1u8; 32]).is_err());
        assert!(!state.is_unlocked());
    }

    #[test]
    fn dropping_a_reservation_without_committing_releases_the_lock() {
        let path = temp_lock_path("reservation");
        let a = instance_at(&path);
        let b = instance_at(&path);
        {
            let _reservation = a.reserve_exclusive().unwrap();
            assert!(b.reserve_exclusive().is_err());
        } // credenciais erradas: a reserva é descartada
        assert!(b.reserve_exclusive().is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn recovery_flag_is_set_only_by_recovery_unlock_and_cleared_by_normal_unlock_or_lock() {
        let state = VaultState::new();
        assert_eq!(state.unlock_method(), None);
        assert!(state.with_recovery_dek(|d| *d).is_none());

        state.set_dek([1u8; 32]).unwrap();
        assert_eq!(state.unlock_method(), Some(UnlockMethod::MasterPassword));
        assert!(state.with_recovery_dek(|d| *d).is_none(), "sessão normal não pode ser tratada como recuperação");

        state.set_dek_from_recovery([2u8; 32]).unwrap();
        assert_eq!(state.unlock_method(), Some(UnlockMethod::Recovery));
        assert_eq!(state.with_recovery_dek(|d| *d), Some([2u8; 32]));

        state.clear();
        assert!(!state.is_unlocked());
        assert!(state.with_recovery_dek(|d| *d).is_none(), "bloquear o cofre tem que apagar o flag de recuperação");

        state.set_dek_from_recovery([3u8; 32]).unwrap();
        state.set_dek([3u8; 32]).unwrap();
        assert!(state.with_recovery_dek(|d| *d).is_none(), "um desbloqueio normal posterior zera o flag");
    }
}
