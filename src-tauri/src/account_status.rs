//! Datas de conta: último login (informado pelo usuário) e selo "Atualizada" (confirmação manual).
//!
//! Todas as contas de tempo usam instantes UTC: a validade do selo é `confirmado_em + 90 × 24 h`
//! exatos, sem passar pelo calendário local — fuso e horário de verão não alteram o prazo. A
//! interface apenas *apresenta* o resultado no fuso local.

use chrono::{DateTime, Duration, NaiveDate, Utc};

pub const BADGE_VALIDITY_DAYS: i64 = 90;
/// Tolerância para pequenas diferenças de relógio entre a gravação e a leitura: uma confirmação
/// "do futuro" além disso é tratada como inválida (nunca exibida como válida).
pub const FUTURE_TOLERANCE_MINUTES: i64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateBadge {
    /// Sem data, data ilegível ou no futuro de forma inconsistente: sem selo.
    None,
    Valid {
        confirmed_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        days_left: i64,
    },
    Expired {
        confirmed_at: DateTime<Utc>,
        expired_at: DateTime<Utc>,
    },
}

pub fn parse_instant(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

pub fn update_badge(confirmed_at: Option<&str>, now: DateTime<Utc>) -> UpdateBadge {
    let Some(raw) = confirmed_at.filter(|s| !s.trim().is_empty()) else {
        return UpdateBadge::None;
    };
    let Some(confirmed) = parse_instant(raw) else {
        return UpdateBadge::None;
    };
    if confirmed > now + Duration::minutes(FUTURE_TOLERANCE_MINUTES) {
        return UpdateBadge::None;
    }
    let expires_at = confirmed + Duration::days(BADGE_VALIDITY_DAYS);
    if now < expires_at {
        // Dias inteiros restantes, arredondando para cima (faltando 1 h, mostra "1 dia").
        let remaining = expires_at - now;
        let days_left = (remaining.num_seconds() + 86_399) / 86_400;
        UpdateBadge::Valid {
            confirmed_at: confirmed,
            expires_at,
            days_left,
        }
    } else {
        UpdateBadge::Expired {
            confirmed_at: confirmed,
            expired_at: expires_at,
        }
    }
}

/// Normaliza a data de último login recebida da interface. Aceita data (`YYYY-MM-DD`, mantida
/// como data de calendário, sem fuso) ou instante RFC 3339 (convertido para UTC). Rejeita
/// formatos inválidos e datas posteriores a "amanhã" (cobre o fuso mais adiantado).
pub fn normalize_last_login(value: &str, now: DateTime<Utc>) -> Result<String, String> {
    let value = value.trim();
    if let Ok(date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        if date > (now + Duration::days(1)).date_naive() {
            return Err("A data do último login não pode estar no futuro.".to_string());
        }
        return Ok(date.format("%Y-%m-%d").to_string());
    }
    if let Some(instant) = parse_instant(value) {
        if instant > now + Duration::days(1) {
            return Err("A data do último login não pode estar no futuro.".to_string());
        }
        return Ok(instant.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    Err("A data do último login é inválida.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    fn iso(d: DateTime<Utc>) -> String {
        d.to_rfc3339()
    }

    #[test]
    fn missing_empty_or_invalid_dates_never_show_a_valid_badge() {
        let now = at(2026, 6, 1, 12, 0);
        assert_eq!(update_badge(None, now), UpdateBadge::None);
        assert_eq!(update_badge(Some(""), now), UpdateBadge::None);
        assert_eq!(update_badge(Some("   "), now), UpdateBadge::None);
        assert_eq!(update_badge(Some("ontem"), now), UpdateBadge::None);
        assert_eq!(
            update_badge(Some("2026-13-45T00:00:00Z"), now),
            UpdateBadge::None
        );
        assert_eq!(
            update_badge(Some("2026-05-01"), now),
            UpdateBadge::None,
            "só instantes RFC 3339 valem"
        );
    }

    #[test]
    fn badge_is_valid_for_ninety_days_and_expires_at_the_exact_boundary() {
        let confirmed = at(2026, 1, 10, 8, 30);
        let c = iso(confirmed);
        let expiry = confirmed + Duration::days(90);

        assert!(matches!(
            update_badge(Some(&c), confirmed),
            UpdateBadge::Valid { days_left: 90, .. }
        ));
        assert!(matches!(
            update_badge(Some(&c), expiry - Duration::seconds(1)),
            UpdateBadge::Valid { days_left: 1, .. }
        ));
        match update_badge(Some(&c), expiry) {
            UpdateBadge::Expired { expired_at, .. } => assert_eq!(expired_at, expiry),
            other => panic!("no instante exato deveria expirar, veio {other:?}"),
        }
        assert!(matches!(
            update_badge(Some(&c), expiry + Duration::days(400)),
            UpdateBadge::Expired { .. }
        ));
    }

    #[test]
    fn expiry_is_computed_in_utc_so_dst_and_time_zones_do_not_shift_it() {
        // Mesmo instante escrito com offsets diferentes expira exatamente junto (90 × 24 h).
        let a = "2026-03-01T00:00:00-03:00"; // = 03:00Z
        let b = "2026-03-01T03:00:00Z";
        let c = "2026-03-01T10:00:00+07:00"; // = 03:00Z
        let boundary = at(2026, 3, 1, 3, 0) + Duration::days(90);
        for s in [a, b, c] {
            assert!(
                matches!(
                    update_badge(Some(s), boundary - Duration::seconds(1)),
                    UpdateBadge::Valid { .. }
                ),
                "{s}"
            );
            assert!(
                matches!(update_badge(Some(s), boundary), UpdateBadge::Expired { .. }),
                "{s}"
            );
        }
        // Atravessa mudanças de horário de verão em qualquer hemisfério: continua 90 × 24 h exatas.
        let confirmed = at(2026, 3, 1, 0, 0);
        assert_eq!(
            (confirmed + Duration::days(90)) - confirmed,
            Duration::hours(90 * 24)
        );
    }

    #[test]
    fn dates_in_the_future_beyond_tolerance_are_not_valid() {
        let now = at(2026, 6, 1, 12, 0);
        assert_eq!(
            update_badge(Some(&iso(now + Duration::days(2))), now),
            UpdateBadge::None
        );
        assert_eq!(
            update_badge(Some(&iso(now + Duration::minutes(6))), now),
            UpdateBadge::None
        );
        assert!(
            matches!(
                update_badge(Some(&iso(now + Duration::minutes(4))), now),
                UpdateBadge::Valid { .. }
            ),
            "pequena folga de relógio"
        );
    }

    #[test]
    fn last_login_accepts_dates_and_instants_and_rejects_bad_or_future_values() {
        let now = at(2026, 6, 1, 12, 0);
        assert_eq!(
            normalize_last_login("2026-05-20", now).unwrap(),
            "2026-05-20"
        );
        assert_eq!(
            normalize_last_login("2026-06-02", now).unwrap(),
            "2026-06-02",
            "fuso mais adiantado ainda pode estar em 'amanhã'"
        );
        assert_eq!(
            normalize_last_login("2026-05-20T10:00:00-03:00", now).unwrap(),
            "2026-05-20T13:00:00Z"
        );
        assert!(normalize_last_login("2026-06-03", now).is_err());
        assert!(normalize_last_login("2027-01-01T00:00:00Z", now).is_err());
        assert!(normalize_last_login("31/12/2025", now).is_err());
        assert!(normalize_last_login("", now).is_err());
        assert!(normalize_last_login("2026-02-30", now).is_err());
    }
}
