//! Exclusividade de cofre desbloqueado entre processos/instâncias do aplicativo.
//!
//! Mecanismo: um arquivo de lock no diretório de dados do app, travado com o lock consultivo
//! exclusivo do sistema operacional (`File::try_lock`: `LockFileEx` no Windows, `flock` no
//! Linux/macOS). O primeiro desbloqueio adquire o lock e o mantém enquanto a sessão existir
//! (guardado dentro da `Session`); bloquear o cofre, o auto-lock e o encerramento do app soltam.
//!
//! Por que lock do SO e não "arquivo com PID" / heartbeat: o SO libera o lock sozinho quando o
//! processo morre (crash, kill, queda de energia), então não existe lock obsoleto para "recuperar"
//! — e, pelo mesmo motivo, nunca se corre o risco de tomar o lock de uma instância que ainda está
//! viva (suspensa, hibernando ou apenas pausada por muito tempo). Não há expiração por tempo.
//!
//! Limites: o lock é por diretório de dados (uma instalação). Duas cópias do app com diretórios de
//! dados diferentes (ex.: perfil isolado) não se enxergam. Locks consultivos não impedem um
//! processo hostil de abrir o banco diretamente — isto coordena instâncias cooperantes do app.
//! Em sistemas de arquivos de rede/sincronizados o comportamento do lock depende do SO/protocolo.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

#[derive(Debug)]
pub enum LockError {
    /// Outra instância (ou outro handle) já mantém o lock.
    Busy,
    Io(String),
}

pub struct InstanceLock {
    file: File,
}

impl InstanceLock {
    pub fn try_acquire(path: &Path) -> Result<Self, LockError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| LockError::Io(e.to_string()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(|e| LockError::Io(e.to_string()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(TryLockError::WouldBlock) => Err(LockError::Busy),
            Err(TryLockError::Error(e)) => Err(LockError::Io(e.to_string())),
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Fechar o handle também libera; o unlock explícito só deixa a intenção clara.
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    /// Os testes que criam processos filhos rodam um de cada vez: no Windows, dois `spawn`
    /// simultâneos podem herdar as pontas de pipe um do outro e o EOF do stdin nunca chega.
    static SPAWN_SERIAL: Mutex<()> = Mutex::new(());

    fn temp_lock_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cofre-instance-lock-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault-unlocked.lock")
    }

    #[test]
    fn second_handle_is_rejected_until_the_first_is_released() {
        let path = temp_lock_path("same-process");
        let first = InstanceLock::try_acquire(&path).unwrap();
        assert!(matches!(
            InstanceLock::try_acquire(&path),
            Err(LockError::Busy)
        ));
        drop(first);
        let again = InstanceLock::try_acquire(&path)
            .expect("liberado ao soltar (bloqueio manual do cofre)");
        drop(again);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Processo filho (reexecuta este mesmo binário de teste): adquire o lock, avisa e espera o pai
    /// fechar o stdin. Só roda quando chamado pelo teste abaixo (`#[ignore]` + variável de ambiente).
    #[test]
    #[ignore = "auxiliar do teste entre processos"]
    fn child_process_holds_lock() {
        let Ok(path) = std::env::var("COFRE_TEST_LOCK_PATH") else {
            return;
        };
        let _guard =
            InstanceLock::try_acquire(Path::new(&path)).expect("filho deveria conseguir o lock");
        println!("LOCKED");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line); // bloqueia até o pai fechar/enviar
    }

    fn spawn_child(path: &Path) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "instance_lock::tests::child_process_holds_lock",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("COFRE_TEST_LOCK_PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("não foi possível iniciar o processo filho de teste")
    }

    fn wait_for_locked(child: &mut std::process::Child) {
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap();
            assert!(n > 0, "o processo filho terminou sem adquirir o lock");
            if line.trim().ends_with("LOCKED") {
                break;
            }
        }
    }

    #[test]
    fn lock_is_exclusive_across_real_processes_and_released_on_clean_exit() {
        let _serial = SPAWN_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let path = temp_lock_path("clean-exit");
        let mut child = spawn_child(&path);
        wait_for_locked(&mut child);

        assert!(
            matches!(InstanceLock::try_acquire(&path), Err(LockError::Busy)),
            "outra instância não pode abrir outro cofre"
        );

        drop(child.stdin.take()); // filho sai normalmente
        child.wait().unwrap();
        InstanceLock::try_acquire(&path).expect("lock liberado depois que o dono encerrou");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn lock_is_released_when_the_owner_is_killed_unexpectedly() {
        let _serial = SPAWN_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let path = temp_lock_path("killed");
        let mut child = spawn_child(&path);
        wait_for_locked(&mut child);
        assert!(matches!(
            InstanceLock::try_acquire(&path),
            Err(LockError::Busy)
        ));

        child.kill().unwrap(); // encerramento inesperado: sem Drop, sem cleanup
        child.wait().unwrap();
        InstanceLock::try_acquire(&path)
            .expect("o SO libera o lock de um processo morto: sem lock obsoleto permanente");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_live_owner_is_never_displaced_by_waiting() {
        // Não existe expiração: mesmo depois de um tempo, enquanto o dono vive o lock continua dele.
        let path = temp_lock_path("live-owner");
        let _owner = InstanceLock::try_acquire(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(matches!(
            InstanceLock::try_acquire(&path),
            Err(LockError::Busy)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
