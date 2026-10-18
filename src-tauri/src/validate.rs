//! Validação de entrada não confiável vinda da WebView (Fase 3 do hardening — ver
//! SECURITY_AUDIT_PHASE_3.md). Todo command que recebe dados da WebView deve tratar esses
//! dados como não confiáveis, mesmo que o React já valide o mesmo campo — a validação real,
//! que protege o banco, é sempre a do lado Rust.

/// Aparam um campo obrigatório: remove espaços nas pontas, rejeita vazio e limita o tamanho
/// (em caracteres, não bytes, para não cortar UTF-8 no meio de um caractere multibyte).
pub fn trim_required(value: &str, field: &str, max_len: usize) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} não pode ficar vazio."));
    }
    if trimmed.chars().count() > max_len {
        return Err(format!("{field} excede o tamanho máximo permitido ({max_len} caracteres)."));
    }
    Ok(trimmed.to_string())
}

/// Como `trim_required`, mas campo vazio vira `None` em vez de erro.
pub fn trim_optional(value: &str, max_len: usize, field: &str) -> Result<Option<String>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > max_len {
        return Err(format!("{field} excede o tamanho máximo permitido ({max_len} caracteres)."));
    }
    Ok(Some(trimmed.to_string()))
}

/// Valida o tamanho de um campo que pode ser opcional e não deve ser aparado (ex.: ciphertext
/// base64 vindo de `secretCommands.encrypt` — aparar espaços corromperia o valor).
pub fn max_len_opt(value: &Option<String>, max_len: usize, field: &str) -> Result<(), String> {
    if let Some(v) = value {
        if v.chars().count() > max_len {
            return Err(format!("{field} excede o tamanho máximo permitido ({max_len} caracteres)."));
        }
    }
    Ok(())
}

pub fn max_len(value: &str, max_len: usize, field: &str) -> Result<(), String> {
    if value.chars().count() > max_len {
        return Err(format!("{field} excede o tamanho máximo permitido ({max_len} caracteres)."));
    }
    Ok(())
}

/// IDs vindos da WebView nunca devem ser confiados como "com certeza aponta pra algo que
/// existe" — mas pelo menos rejeitamos valores estruturalmente inválidos (zero/negativos) antes
/// de gastar uma query. Uma query que não encontra a linha simplesmente não afeta nada
/// (`UPDATE ... WHERE id = ?` com 0 linhas afetadas não é um erro do SQLite).
pub fn positive_id(id: i64, field: &str) -> Result<(), String> {
    if id <= 0 {
        return Err(format!("{field} inválido."));
    }
    Ok(())
}

/// Valida que um valor está dentro de uma allowlist fixa (status de conta, método de 2FA, tipo
/// de propriedade, escopo de listagem, chave de configuração...). Nunca aceita um valor livre
/// vindo da WebView para colunas que a UI trata como enum fechado.
pub fn one_of<'a>(value: &str, allowed: &[&'a str], field: &str) -> Result<&'a str, String> {
    allowed
        .iter()
        .find(|candidate| **candidate == value)
        .copied()
        .ok_or_else(|| format!("{field} inválido."))
}

pub fn one_of_opt<'a>(value: Option<&str>, allowed: &[&'a str], field: &str) -> Result<Option<&'a str>, String> {
    match value {
        None => Ok(None),
        Some(v) => one_of(v, allowed, field).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_required_rejects_empty_and_too_long() {
        assert!(trim_required("   ", "Nome", 10).is_err());
        assert!(trim_required(&"a".repeat(11), "Nome", 10).is_err());
        assert_eq!(trim_required("  ok  ", "Nome", 10).unwrap(), "ok");
    }

    #[test]
    fn trim_optional_turns_blank_into_none() {
        assert_eq!(trim_optional("   ", 10, "Campo").unwrap(), None);
        assert_eq!(trim_optional(" x ", 10, "Campo").unwrap(), Some("x".to_string()));
    }

    #[test]
    fn positive_id_rejects_zero_and_negative() {
        assert!(positive_id(0, "id").is_err());
        assert!(positive_id(-1, "id").is_err());
        assert!(positive_id(1, "id").is_ok());
    }

    #[test]
    fn one_of_rejects_values_outside_allowlist() {
        let allowed = ["active", "trash", "all"];
        assert_eq!(one_of("active", &allowed, "scope").unwrap(), "active");
        assert!(one_of("'; DROP TABLE accounts;--", &allowed, "scope").is_err());
    }
}
