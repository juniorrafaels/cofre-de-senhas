//! Hook nativo do Windows para forçar o bloqueio do cofre IMEDIATAMENTE quando o Windows
//! bloqueia a sessão (Win+L) ou o sistema suspende — em vez de depender só do relógio de
//! parede que o lado JS confere na próxima vez que a janela ganha foco (`useAutoLock.ts`).
//! Ver SECURITY_AUDIT_PHASE_3.md, seções "Windows Lock"/"Suspend"/"Zeroization".
//!
//! Superfície `unsafe` deliberadamente pequena e isolada neste único arquivo: registra a janela
//! principal para receber `WM_WTSSESSION_CHANGE` (bloqueio/desbloqueio de sessão do Windows) e
//! intercepta `WM_POWERBROADCAST` (suspensão/retomada) via `SetWindowSubclass`, chamando
//! `VaultState::clear()` diretamente do callback nativo assim que um desses eventos chega — sem
//! depender do JS/WebView ainda estar responsivo para reagir.
//!
//! Falha ao registrar (API indisponível, `HWND` não resolvido, etc.) nunca é fatal: só loga em
//! stderr e o app segue com a mitigação por relógio de parede do lado JS como única linha de
//! defesa, exatamente como antes desta fase (ver `SECURITY_AUDIT_PHASE_2.md`).

#[cfg(target_os = "windows")]
mod imp {
    use crate::state::VaultState;
    use std::sync::OnceLock;
    use tauri::{AppHandle, Manager};
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::RemoteDesktop::{NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification};
    use windows::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass, SUBCLASSPROC};
    use windows::Win32::UI::WindowsAndMessaging::{PBT_APMSUSPEND, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK};

    const SUBCLASS_ID: usize = 1;

    // A janela principal vive pela vida inteira do processo (não há hide-to-tray nem
    // multi-janela neste app), então não existe um momento seguro/necessário para "desregistrar"
    // antes de encerrar — o processo termina e o SO libera a notificação de sessão e o subclass
    // junto com o HWND. Por isso não guardamos um destrutor: o único estado que este módulo
    // precisa manter vivo é o `AppHandle` usado pelo callback nativo.
    static APP_HANDLE: OnceLock<AppHandle> = OnceLock::new();

    unsafe extern "system" fn subclass_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        _uidsubclass: usize,
        _dwrefdata: usize,
    ) -> LRESULT {
        let should_lock = match msg {
            WM_WTSSESSION_CHANGE => wparam.0 as u32 == WTS_SESSION_LOCK,
            WM_POWERBROADCAST => wparam.0 as u32 == PBT_APMSUSPEND,
            _ => false,
        };
        if should_lock {
            if let Some(app) = APP_HANDLE.get() {
                app.state::<VaultState>().clear();
            }
        }
        unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
    }

    /// Chamado uma vez em `.setup()`. Nunca propaga erro — o pior caso aceitável é "o hook
    /// nativo não foi instalado", nunca "o app falhou ao iniciar por causa de um hardening
    /// best-effort".
    pub fn install(app: &AppHandle) {
        let Some(window) = app.get_webview_window("main") else {
            eprintln!("[native_lock] janela principal não encontrada; hook nativo de lock/suspend não instalado.");
            return;
        };
        let Ok(hwnd) = window.hwnd() else {
            eprintln!("[native_lock] não foi possível obter o HWND da janela; hook nativo de lock/suspend não instalado.");
            return;
        };

        let _ = APP_HANDLE.set(app.clone());

        // unsafe: chamadas diretas de Win32 API (WTS session notifications + window subclassing).
        // `SetWindowSubclass` é o mesmo mecanismo usado internamente por bibliotecas maduras como
        // `tao`/`winit` para observar mensagens de uma janela sem substituir seu WndProc original
        // — sempre repassamos ao final para `DefSubclassProc`, então mensagens de
        // mouse/teclado/IME que o WebView2 precisa continuam fluindo normalmente.
        //
        // Falha em qualquer uma destas chamadas é tratada como não-fatal (ver doc do módulo).
        if let Err(e) = unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } {
            eprintln!(
                "[native_lock] WTSRegisterSessionNotification falhou ({e}); bloqueio automático ao Win+L pode não ser imediato (o relógio de parede do lado JS ainda cobre o caso ao restaurar o foco)."
            );
        }

        let proc: SUBCLASSPROC = Some(subclass_proc);
        let ok = unsafe { SetWindowSubclass(hwnd, proc, SUBCLASS_ID, 0) };
        if !ok.as_bool() {
            eprintln!(
                "[native_lock] SetWindowSubclass falhou; hook nativo de lock/suspend não instalado, mantendo apenas a mitigação por relógio de parede do lado JS."
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    pub fn install(_app: &tauri::AppHandle) {}
}

pub use imp::install;
