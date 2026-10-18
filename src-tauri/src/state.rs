use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

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
}

pub struct VaultState {
    // DEK e método de desbloqueio ficam sob o MESMO mutex para que nunca exista uma janela em que
    // a DEK de uma sessão normal conviva com o flag de recuperação de uma sessão anterior.
    session: Mutex<Option<Session>>,
    pub reveal_limiter: RevealLimiter,
}

impl VaultState {
    pub fn new() -> Self {
        Self { session: Mutex::new(None), reveal_limiter: RevealLimiter::new(Duration::from_secs(10), 25) }
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.lock().unwrap().is_some()
    }

    /// Desbloqueio normal (senha mestra / criação do cofre / troca de senha reautenticada).
    /// Sempre zera o flag de recuperação.
    pub fn set_dek(&self, dek: [u8; 32]) {
        *self.session.lock().unwrap() = Some(Session { dek: Zeroizing::new(dek), method: UnlockMethod::MasterPassword });
    }

    /// Desbloqueio por um mecanismo de recuperação bem-sucedido (Recovery Key ou perguntas de
    /// segurança). Só estes dois caminhos podem chamar isto.
    pub fn set_dek_from_recovery(&self, dek: [u8; 32]) {
        *self.session.lock().unwrap() = Some(Session { dek: Zeroizing::new(dek), method: UnlockMethod::Recovery });
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

    #[test]
    fn recovery_flag_is_set_only_by_recovery_unlock_and_cleared_by_normal_unlock_or_lock() {
        let state = VaultState::new();
        assert_eq!(state.unlock_method(), None);
        assert!(state.with_recovery_dek(|d| *d).is_none());

        state.set_dek([1u8; 32]);
        assert_eq!(state.unlock_method(), Some(UnlockMethod::MasterPassword));
        assert!(state.with_recovery_dek(|d| *d).is_none(), "sessão normal não pode ser tratada como recuperação");

        state.set_dek_from_recovery([2u8; 32]);
        assert_eq!(state.unlock_method(), Some(UnlockMethod::Recovery));
        assert_eq!(state.with_recovery_dek(|d| *d), Some([2u8; 32]));

        state.clear();
        assert!(!state.is_unlocked());
        assert!(state.with_recovery_dek(|d| *d).is_none(), "bloquear o cofre tem que apagar o flag de recuperação");

        state.set_dek_from_recovery([3u8; 32]);
        state.set_dek([3u8; 32]);
        assert!(state.with_recovery_dek(|d| *d).is_none(), "um desbloqueio normal posterior zera o flag");
    }
}
