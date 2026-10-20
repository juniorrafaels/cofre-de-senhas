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

/// Caracteres que tornam uma URL ambígua ou enganosa para quem a lê: controles, espaços, barra
/// invertida (o parser WHATWG a trata como `/`, outros parsers e o shell do Windows não) e
/// caracteres Unicode invisíveis ou de direção (U+202E inverte visualmente o texto).
fn is_deceptive_url_char(c: char) -> bool {
    c.is_control()
        || c.is_whitespace()
        || c == '\\'
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

/// Como `trim_optional`, mas exige que o valor seja uma URL absoluta `https://` ou `http://` com
/// host. Rejeita `javascript:`, `file:`, `data:`, esquemas desconhecidos, URLs sem esquema
/// ("example.com"), entradas malformadas, barra invertida, caracteres invisíveis/bidi e
/// usuário/senha embutidos (`https://usuario:senha@host`: ficaria em texto claro no banco e
/// `https://site.com@outro.com` engana quem lê o host). `http://` continua aceito por
/// compatibilidade com cofres existentes (ver SECURITY.md); IPv6, IPv4, localhost, IDN e portas
/// válidas continuam aceitos.
///
/// O plugin opener do Tauri compara a string **crua** com o escopo (glob, sensível a maiúsculas) e
/// a entrega crua ao sistema operacional. Por isso o esquema é devolvido em minúsculas
/// (`HTTPS://x` → `https://x`, normalização de uma URL válida) e nada que o parser aceite mas o
/// shell interprete diferente passa daqui.
pub fn http_url_optional(value: &str, max_len: usize, field: &str) -> Result<Option<String>, String> {
    let Some(trimmed) = trim_optional(value, max_len, field)? else {
        return Ok(None);
    };
    let invalid = || {
        format!(
            "{field} deve ser um endereço completo começando com https:// (ou http://), sem espaços, barras invertidas, usuário/senha ou caracteres invisíveis."
        )
    };
    if trimmed.chars().any(is_deceptive_url_char) {
        return Err(invalid());
    }
    // O parser WHATWG é leniente com esquemas "especiais" (`http:///x` vira host `x`, `https:host`
    // e `https:\\host` também são aceitos). Exigimos `esquema://` literal seguido do host.
    let lower = trimmed.to_ascii_lowercase();
    let (scheme, after_scheme) = if let Some(rest) = lower.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(invalid());
    };
    if after_scheme.is_empty() || after_scheme.starts_with('/') {
        return Err(invalid());
    }
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid());
    }
    let parsed = url::Url::parse(&trimmed).map_err(|_| invalid())?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none_or(str::is_empty) {
        return Err(invalid());
    }
    Ok(Some(format!("{scheme}://{}", &trimmed[scheme.len() + 3..])))
}

/// Como `http_url_optional`, mas um valor **idêntico** ao que já está gravado (`existing`, lido do
/// banco pelo próprio Rust, nunca enviado pela WebView) é mantido como está, sem revalidar. Assim
/// uma conta antiga com URL inválida pelas regras novas continua editável nos outros campos, sem
/// reescrever nem apagar a URL. Qualquer valor diferente do gravado (novo ou alterado) passa pela
/// validação completa, então nenhuma URL nova ou alterada escapa da regra por já existir outra
/// parecida no banco.
pub fn http_url_optional_keeping_legacy(
    value: &str,
    existing: Option<&str>,
    max_len: usize,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(trimmed) = trim_optional(value, max_len, field)? else {
        return Ok(None);
    };
    if existing == Some(trimmed.as_str()) {
        return Ok(Some(trimmed));
    }
    http_url_optional(&trimmed, max_len, field)
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

    #[derive(serde::Deserialize)]
    struct UrlCases {
        accept: Vec<String>,
        reject: Vec<String>,
    }

    // Casos compartilhados com o frontend (`src/lib/__tests__/externalUrl.test.ts`): o validador do
    // Rust e o `isAllowedExternalUrl` do TypeScript precisam concordar em todos.
    fn shared_cases() -> UrlCases {
        serde_json::from_str(include_str!("../../test-fixtures/external-urls.json")).unwrap()
    }

    #[test]
    fn http_url_optional_accepts_shared_legitimate_urls() {
        for ok in shared_cases().accept {
            assert!(http_url_optional(&ok, 2048, "URL").is_ok(), "deveria aceitar: {ok:?}");
        }
    }

    #[test]
    fn http_url_optional_rejects_shared_dangerous_unknown_and_malformed_urls() {
        for bad in shared_cases().reject {
            assert!(http_url_optional(&bad, 2048, "URL").is_err(), "deveria rejeitar: {bad:?}");
        }
    }

    #[test]
    fn http_url_optional_blank_trim_and_scheme_normalization() {
        assert_eq!(http_url_optional("  ", 2048, "URL").unwrap(), None);
        assert_eq!(
            http_url_optional(" https://example.com/login?a=1 ", 2048, "URL").unwrap(),
            Some("https://example.com/login?a=1".to_string())
        );
        // Só o esquema é normalizado (o plugin opener compara a string crua, sensível a maiúsculas).
        assert_eq!(
            http_url_optional("HTTPS://Example.COM/Path", 2048, "URL").unwrap().as_deref(),
            Some("https://Example.COM/Path")
        );
        assert_eq!(http_url_optional("HtTp://localhost:1420", 2048, "URL").unwrap().as_deref(), Some("http://localhost:1420"));
    }

    #[test]
    fn http_url_optional_rejects_oversized_value() {
        assert!(http_url_optional(&format!("https://example.com/{}", "a".repeat(2048)), 2048, "URL").is_err());
    }

    #[test]
    fn http_url_optional_error_message_is_the_one_the_frontend_translates() {
        let e = http_url_optional("javascript:alert(1)", 2048, "A URL de login").unwrap_err();
        assert_eq!(
            e,
            "A URL de login deve ser um endereço completo começando com https:// (ou http://), sem espaços, barras invertidas, usuário/senha ou caracteres invisíveis."
        );
    }

    #[test]
    fn legacy_url_unchanged_is_kept_but_any_change_is_fully_validated() {
        let legacy = "example.com"; // inválida pelas regras novas, mas já está no banco
        // Idêntica à gravada: mantida, sem reescrever.
        assert_eq!(
            http_url_optional_keeping_legacy("  example.com ", Some(legacy), 2048, "URL").unwrap().as_deref(),
            Some("example.com")
        );
        // Alterada para algo perigoso ou inválido: rejeitada.
        assert!(http_url_optional_keeping_legacy("javascript:alert(1)", Some(legacy), 2048, "URL").is_err());
        assert!(http_url_optional_keeping_legacy("example.org", Some(legacy), 2048, "URL").is_err());
        // Alterada para uma URL válida: aceita.
        assert!(http_url_optional_keeping_legacy("https://example.org", Some(legacy), 2048, "URL").is_ok());
        // A WebView não pode "herdar" a exceção: sem valor gravado igual, vale a regra completa.
        assert!(http_url_optional_keeping_legacy("example.com", None, 2048, "URL").is_err());
        assert!(http_url_optional_keeping_legacy("javascript:alert(1)", Some("https://ok.com"), 2048, "URL").is_err());
        // Apagar a URL é sempre permitido.
        assert_eq!(http_url_optional_keeping_legacy("", Some(legacy), 2048, "URL").unwrap(), None);
        // O limite de tamanho continua valendo mesmo para valor legado.
        let long = format!("x{}", "a".repeat(2048));
        assert!(http_url_optional_keeping_legacy(&long, Some(&long), 2048, "URL").is_err());
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
