use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

const COPY_FAILED: &str = "Não foi possível copiar para a área de transferência.";

/// Escreve no clipboard e, opcionalmente, agenda a limpeza automática — caminho para valores NÃO
/// secretos (usuário, e-mail, URL...). Usa o plugin do Tauri.
pub(crate) fn write_and_schedule_clear(app: &AppHandle, text: String, clear_after_seconds: Option<u64>) -> Result<(), String> {
    plugin_write_and_schedule_clear(app, Zeroizing::new(text), clear_after_seconds)
}

/// Caminho para SEGREDOS (senha de conta, propriedade sensível, senha gerada, Recovery Key).
/// `pub(crate)` (não um `#[tauri::command]`) porque é reaproveitada internamente por
/// `accounts::copy_account_password` e `properties::copy_sensitive_property` — cada um decifra o
/// segredo específico que já buscou no SQLite e só então chama esta função; nenhum ciphertext
/// arbitrário chega até aqui vindo da WebView (Fase 4 — ver SECURITY_AUDIT_PHASE_4.md).
///
/// No Windows, o texto é gravado junto com os formatos que pedem ao sistema para NÃO guardar o
/// conteúdo no Histórico da Área de Transferência (Win+V) nem sincronizá-lo com a nuvem, e para
/// gerenciadores de clipboard ignorarem o conteúdo (ver `windows_secret_clipboard`). Isso é um
/// pedido respeitado pelo Windows e por apps bem-comportados — não uma garantia contra malware.
/// Nas demais plataformas, cai no mesmo caminho do plugin.
pub(crate) fn write_secret_and_schedule_clear(app: &AppHandle, secret: Zeroizing<String>, clear_after_seconds: Option<u64>) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = app; // o caminho Win32 não precisa do AppHandle
        let units = utf16_nul_terminated(&secret);
        let sequence = windows_secret_clipboard::set_secret_text(&units).map_err(|_| COPY_FAILED.to_string())?;
        if let Some(seconds) = clear_after_seconds.filter(|s| *s > 0) {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(seconds));
                // Só limpa se o clipboard ainda contém o que NÓS copiamos (mesmo número de
                // sequência, ou mesmo texto) — nunca apaga algo que o usuário copiou depois.
                windows_secret_clipboard::clear_if_still_ours(sequence, &units);
                drop(units); // Zeroizing: sobrescreve a cópia UTF-16 local do segredo
            });
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        plugin_write_and_schedule_clear(app, secret, clear_after_seconds)
    }
}

fn plugin_write_and_schedule_clear(app: &AppHandle, text: Zeroizing<String>, clear_after_seconds: Option<u64>) -> Result<(), String> {
    app.clipboard().write_text(text.to_string()).map_err(|_| COPY_FAILED.to_string())?;

    if let Some(seconds) = clear_after_seconds {
        if seconds > 0 {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                // Só limpa se o clipboard ainda contiver o mesmo valor copiado, para não apagar
                // algo que o usuário copiou depois. Esta leitura é interna ao processo Rust (não
                // passa pela ACL de IPC) — a WebView não tem mais permissão para ler o clipboard
                // diretamente (ver `capabilities/default.json`, removido `allow-read-text`).
                if let Ok(current) = app.clipboard().read_text() {
                    let current = Zeroizing::new(current);
                    if *current == *text {
                        let _ = app.clipboard().clear();
                    }
                }
            });
        }
    }

    Ok(())
}

/// `sensitive: true` → caminho de segredo (ver `write_secret_and_schedule_clear`). Usado pela UI
/// para valores que já estão na WebView por natureza (senha recém-gerada, Recovery Key exibida
/// uma única vez). Senhas/propriedades salvas usam os commands por ID, nunca este.
#[tauri::command]
pub fn copy_to_clipboard(app: AppHandle, text: String, clear_after_seconds: Option<u64>, sensitive: Option<bool>) -> Result<(), String> {
    if sensitive.unwrap_or(false) {
        write_secret_and_schedule_clear(&app, Zeroizing::new(text), clear_after_seconds)
    } else {
        write_and_schedule_clear(&app, text, clear_after_seconds)
    }
}

/// Texto em UTF-16 terminado em NUL — o formato exigido por `CF_UNICODETEXT`.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn utf16_nul_terminated(text: &str) -> Zeroizing<Vec<u16>> {
    let mut units: Vec<u16> = Vec::with_capacity(text.len() + 1);
    units.extend(text.encode_utf16());
    units.push(0);
    Zeroizing::new(units)
}

/// Conteúdo dos formatos de "dica" para o Windows: um DWORD (u32 little-endian). Valor 0 em
/// `CanIncludeInClipboardHistory`/`CanUploadToCloudClipboard` significa "não permitir"; para
/// `ExcludeClipboardContentFromMonitorProcessing` só a presença do formato importa.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn dword_payload(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Nomes dos formatos registrados de clipboard usados para marcar o conteúdo como sensível.
/// Documentados pela Microsoft em "Clipboard Formats" → "Cloud Clipboard and Clipboard History
/// Formats".
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const EXCLUDE_FROM_MONITORS_FORMAT: &str = "ExcludeClipboardContentFromMonitorProcessing";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const CAN_INCLUDE_IN_HISTORY_FORMAT: &str = "CanIncludeInClipboardHistory";
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const CAN_UPLOAD_TO_CLOUD_FORMAT: &str = "CanUploadToCloudClipboard";

/// Os três formatos de dica e seus payloads (todos DWORD 0).
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn secret_hint_formats() -> [(&'static str, [u8; 4]); 3] {
    [
        (EXCLUDE_FROM_MONITORS_FORMAT, dword_payload(0)),
        (CAN_INCLUDE_IN_HISTORY_FORMAT, dword_payload(0)),
        (CAN_UPLOAD_TO_CLOUD_FORMAT, dword_payload(0)),
    ]
}

#[cfg(windows)]
mod windows_secret_clipboard {
    //! Escrita do segredo via Win32 em uma ÚNICA sessão OpenClipboard → EmptyClipboard →
    //! SetClipboardData(dicas + CF_UNICODETEXT) → CloseClipboard, para que o Histórico (Win+V) e
    //! a sincronização na nuvem vejam as dicas junto com o texto. Nenhuma função aqui loga ou
    //! devolve o segredo; erros viram `Err(())` e o chamador devolve uma mensagem genérica.
    use super::secret_hint_formats;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard,
        RegisterClipboardFormatW, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    /// Fecha o clipboard ao sair de escopo (inclusive em erro), para nunca deixá-lo travado.
    struct OpenedClipboard;

    impl OpenedClipboard {
        fn open() -> Result<Self, ()> {
            // Outro processo pode estar com o clipboard aberto por alguns ms: tenta algumas vezes.
            for _ in 0..10 {
                if unsafe { OpenClipboard(None) }.is_ok() {
                    return Ok(Self);
                }
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            Err(())
        }
    }

    impl Drop for OpenedClipboard {
        fn drop(&mut self) {
            let _ = unsafe { CloseClipboard() };
        }
    }

    /// Copia `bytes` para um bloco GMEM_MOVEABLE e entrega ao clipboard. Em caso de falha, zera o
    /// bloco antes de liberá-lo (pode conter o segredo).
    fn set_bytes(format: u32, bytes: &[u8]) -> Result<(), ()> {
        unsafe {
            let handle = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)).map_err(|_| ())?;
            let ptr = GlobalLock(handle) as *mut u8;
            if ptr.is_null() {
                let _ = GlobalFree(Some(handle));
                return Err(());
            }
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            let _ = GlobalUnlock(handle);

            if SetClipboardData(format, Some(HANDLE(handle.0))).is_err() {
                zero_and_free(handle, bytes.len());
                return Err(());
            }
            // Sucesso: o bloco agora pertence ao sistema — não pode ser liberado aqui.
            Ok(())
        }
    }

    unsafe fn zero_and_free(handle: HGLOBAL, len: usize) {
        unsafe {
            let ptr = GlobalLock(handle) as *mut u8;
            if !ptr.is_null() {
                std::ptr::write_bytes(ptr, 0, len);
                let _ = GlobalUnlock(handle);
            }
            let _ = GlobalFree(Some(handle));
        }
    }

    fn as_bytes(units: &[u16]) -> &[u8] {
        // SAFETY: u16 não tem padding; reinterpretar como bytes (mesma memória, 2x o tamanho).
        unsafe { std::slice::from_raw_parts(units.as_ptr() as *const u8, std::mem::size_of_val(units)) }
    }

    /// Grava o segredo (UTF-16 com NUL) + as três dicas. Retorna o número de sequência do
    /// clipboard logo após a gravação, usado depois para saber se o conteúdo ainda é o nosso.
    pub fn set_secret_text(units_with_nul: &[u16]) -> Result<u32, ()> {
        {
            let _clipboard = OpenedClipboard::open()?;
            unsafe { EmptyClipboard() }.map_err(|_| ())?;

            for (name, payload) in secret_hint_formats() {
                let format = unsafe { RegisterClipboardFormatW(&HSTRING::from(name)) };
                // Best-effort: se o registro falhar (0), o texto ainda é copiado — mesma proteção
                // que a versão anterior (plugin), só sem a dica.
                if format != 0 {
                    let _ = set_bytes(format, &payload);
                }
            }

            set_bytes(u32::from(CF_UNICODETEXT.0), as_bytes(units_with_nul))?;
        } // CloseClipboard aqui — só então o Windows decide sobre histórico/nuvem.
        Ok(unsafe { GetClipboardSequenceNumber() })
    }

    /// Compara o texto atual do clipboard com o segredo SEM copiá-lo para fora do bloco global.
    fn current_text_equals(secret_with_nul: &[u16]) -> bool {
        let format = u32::from(CF_UNICODETEXT.0);
        unsafe {
            if IsClipboardFormatAvailable(format).is_err() {
                return false;
            }
            let Ok(handle) = GetClipboardData(format) else { return false };
            let global = HGLOBAL(handle.0);
            let ptr = GlobalLock(global) as *const u16;
            if ptr.is_null() {
                return false;
            }
            let capacity = GlobalSize(global) / 2;
            let current = std::slice::from_raw_parts(ptr, capacity);
            let current_len = current.iter().position(|&c| c == 0).unwrap_or(capacity);
            let secret = &secret_with_nul[..secret_with_nul.len().saturating_sub(1)];
            let equal = &current[..current_len] == secret;
            let _ = GlobalUnlock(global);
            equal
        }
    }

    /// Limpa o clipboard só se ele ainda contém o que copiamos: mesmo número de sequência (nada
    /// mudou desde a nossa gravação) ou, se algo regravou o clipboard, o mesmo texto.
    pub fn clear_if_still_ours(sequence_after_write: u32, secret_with_nul: &[u16]) {
        let Ok(_clipboard) = OpenedClipboard::open() else { return };
        let unchanged = unsafe { GetClipboardSequenceNumber() } == sequence_after_write;
        if unchanged || current_text_equals(secret_with_nul) {
            let _ = unsafe { EmptyClipboard() };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// TESTE MANUAL (ignorado por padrão porque mexe no clipboard REAL do usuário):
        /// `cargo test --lib -- --ignored secret_copy_sets_hint_formats_and_clears` — grava um
        /// valor sintético, confere que os três formatos de dica estão presentes junto com o
        /// texto, e limpa.
        #[test]
        #[ignore]
        fn secret_copy_sets_hint_formats_and_clears() {
            let units = super::super::utf16_nul_terminated("SYNTHETIC_CLIPBOARD_TEST_VALUE_000");
            let seq = set_secret_text(&units).expect("falha ao gravar no clipboard");
            {
                let _c = OpenedClipboard::open().unwrap();
                for (name, _) in secret_hint_formats() {
                    let format = unsafe { RegisterClipboardFormatW(&HSTRING::from(name)) };
                    assert!(unsafe { IsClipboardFormatAvailable(format) }.is_ok(), "formato {name} ausente");
                }
                assert!(current_text_equals(&units));
            }
            clear_if_still_ours(seq, &units);
            let _c = OpenedClipboard::open().unwrap();
            assert!(!current_text_equals(&units), "o clipboard deveria ter sido limpo");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dword_payload_is_little_endian_u32() {
        assert_eq!(dword_payload(0), [0, 0, 0, 0]);
        assert_eq!(dword_payload(1), [1, 0, 0, 0]);
        assert_eq!(dword_payload(0x0102_0304), [4, 3, 2, 1]);
    }

    #[test]
    fn secret_hint_formats_are_the_documented_names_with_zero_dwords() {
        let formats = secret_hint_formats();
        let names: Vec<&str> = formats.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec!["ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"]
        );
        assert!(formats.iter().all(|(_, payload)| *payload == [0, 0, 0, 0]), "0 = não permitir histórico/nuvem");
    }

    #[test]
    fn utf16_buffer_is_nul_terminated_and_preserves_non_ascii() {
        let units = utf16_nul_terminated("Señh@ção🔑");
        assert_eq!(*units.last().unwrap(), 0);
        assert_eq!(String::from_utf16(&units[..units.len() - 1]).unwrap(), "Señh@ção🔑");
        assert_eq!(utf16_nul_terminated("").as_slice(), &[0]);
    }
}
