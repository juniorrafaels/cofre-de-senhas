use crate::db;
use crate::state::VaultState;
use rusqlite::params;
use std::collections::HashMap;
use tauri::{AppHandle, State};

const VALUE_MAX: usize = 4000;

const THEME_VALUES: &[&str] = &["light", "dark", "system"];
// Idiomas suportados pela interface (seção de i18n). `pt-BR` é sempre o padrão/fallback do
// frontend — ver useSettingsStore.ts.
const LANGUAGE_VALUES: &[&str] = &["pt-BR", "en", "es"];
const BOOL_VALUES: &[&str] = &["true", "false"];
const VIEW_MODE_VALUES: &[&str] = &["grid", "list"];
const LIST_COLUMN_KEYS: &[&str] =
    &["avatar", "name", "platform", "username", "email", "project", "status", "tags", "updated_at", "two_factor", "last_login"];
// Níveis discretos do controle de escala das listagens/cards (seção 4 do pedido de ajuste) —
// nunca zoom livre, para não permitir um valor que quebre o layout.
const LIST_SCALE_VALUES: &[&str] = &["75", "90", "100", "110", "125", "150", "175", "200"];

fn require_unlocked(state: &State<VaultState>) -> Result<(), String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    Ok(())
}

/// A tabela `settings` é um key/value genérico no schema, mas a WebView só deve conseguir
/// gravar as chaves que o app realmente usa (ver `useSettingsStore.ts`) — nunca uma chave
/// arbitrária — e cada valor é validado de acordo com o formato esperado por aquela chave
/// específica. Isso evita que uma WebView comprometida use este command como um "KV store
/// genérico" para persistir qualquer coisa.
fn validate_setting(key: &str, value: &str) -> Result<(), String> {
    if value.chars().count() > VALUE_MAX {
        return Err("O valor da configuração excede o tamanho máximo permitido.".to_string());
    }
    match key {
        "theme" => {
            if !THEME_VALUES.contains(&value) {
                return Err("Tema inválido.".to_string());
            }
        }
        "language" => {
            if !LANGUAGE_VALUES.contains(&value) {
                return Err("Idioma inválido.".to_string());
            }
        }
        // `show_updated_badge`: exibe/oculta o selo "Atualizada" (preferência de exibição — nunca altera
        // `update_confirmed_at`). A coluna "Último login" é controlada por `list_columns` ("last_login").
        "lock_on_minimize" | "clipboard_clear_enabled" | "show_updated_badge" => {
            if !BOOL_VALUES.contains(&value) {
                return Err("Valor booleano inválido.".to_string());
            }
        }
        "auto_lock_minutes" | "clipboard_clear_seconds" => {
            let parsed: i64 = value.parse().map_err(|_| "Valor numérico inválido.".to_string())?;
            if !(0..=10_080).contains(&parsed) {
                return Err("Valor numérico fora do intervalo permitido.".to_string());
            }
        }
        "view_mode" => {
            if !VIEW_MODE_VALUES.contains(&value) {
                return Err("Modo de visualização inválido.".to_string());
            }
        }
        "list_scale" => {
            if !LIST_SCALE_VALUES.contains(&value) {
                return Err("Escala de visualização inválida.".to_string());
            }
        }
        "list_columns" => {
            let parsed: serde_json::Value = serde_json::from_str(value).map_err(|_| "Lista de colunas inválida.".to_string())?;
            let array = parsed.as_array().ok_or_else(|| "Lista de colunas inválida.".to_string())?;
            for item in array {
                let key = item.as_str().ok_or_else(|| "Lista de colunas inválida.".to_string())?;
                if !LIST_COLUMN_KEYS.contains(&key) {
                    return Err("Lista de colunas contém uma coluna desconhecida.".to_string());
                }
            }
        }
        _ => return Err("Chave de configuração desconhecida.".to_string()),
    }
    Ok(())
}

#[tauri::command]
pub fn get_all_settings(app: AppHandle, state: State<VaultState>) -> Result<HashMap<String, String>, String> {
    require_unlocked(&state)?;
    let conn = db::open(&app)?;
    let mut stmt = conn.prepare("SELECT key, value FROM settings").map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().collect())
}

#[tauri::command]
pub fn set_setting(app: AppHandle, state: State<VaultState>, key: String, value: String) -> Result<(), String> {
    require_unlocked(&state)?;
    validate_setting(&key, &value)?;
    let conn = db::open(&app)?;
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
        params![key, value],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_setting_keys() {
        assert!(validate_setting("arbitrary_key", "anything").is_err());
    }

    #[test]
    fn accepts_only_supported_languages() {
        assert!(validate_setting("language", "pt-BR").is_ok());
        assert!(validate_setting("language", "en").is_ok());
        assert!(validate_setting("language", "es").is_ok());
        assert!(validate_setting("language", "fr").is_err());
        assert!(validate_setting("language", "").is_err());
    }

    #[test]
    fn rejects_out_of_range_numeric_settings() {
        assert!(validate_setting("auto_lock_minutes", "-1").is_err());
        assert!(validate_setting("auto_lock_minutes", "999999").is_err());
        assert!(validate_setting("auto_lock_minutes", "5").is_ok());
    }

    #[test]
    fn rejects_unknown_list_columns() {
        assert!(validate_setting("list_columns", r#"["name","evil_column"]"#).is_err());
        assert!(validate_setting("list_columns", r#"["name","status"]"#).is_ok());
    }

    #[test]
    fn last_login_column_and_updated_badge_are_independent_display_settings() {
        assert!(validate_setting("list_columns", r#"["name","last_login"]"#).is_ok());
        assert!(validate_setting("list_columns", r#"["name"]"#).is_ok(), "ocultar a coluna é só tirá-la da lista");
        assert!(validate_setting("show_updated_badge", "true").is_ok());
        assert!(validate_setting("show_updated_badge", "false").is_ok());
        assert!(validate_setting("show_updated_badge", "talvez").is_err());
    }

    #[test]
    fn security_policies_are_not_writable_through_the_generic_settings_command() {
        // Política de duas senhas e bloqueio progressivo vivem no backend (com reautenticação); a
        // WebView não pode "ligar/desligar" via set_setting.
        for key in ["unlock_policy", "dual_unlock", "throttle_enabled", "unlock_throttle", "recovery_password"] {
            assert!(validate_setting(key, "true").is_err(), "{key}");
        }
    }

    #[test]
    fn rejects_non_boolean_values_for_boolean_settings() {
        assert!(validate_setting("lock_on_minimize", "maybe").is_err());
        assert!(validate_setting("lock_on_minimize", "true").is_ok());
    }

    #[test]
    fn rejects_list_scale_values_outside_the_discrete_levels() {
        assert!(validate_setting("list_scale", "60").is_err());
        assert!(validate_setting("list_scale", "140").is_err());
        assert!(validate_setting("list_scale", "201").is_err());
        assert!(validate_setting("list_scale", "100").is_ok());
        assert!(validate_setting("list_scale", "125").is_ok());
        assert!(validate_setting("list_scale", "150").is_ok());
        assert!(validate_setting("list_scale", "175").is_ok());
        assert!(validate_setting("list_scale", "200").is_ok());
    }
}
