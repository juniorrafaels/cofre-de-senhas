//! Compartilhamento de segredo de Shamir sobre GF(2^8), usado pelas perguntas de segurança.
//!
//! Substitui a crate `sharks` 0.5.0 (RUSTSEC-2024-0398 / GHSA-jp37-5qhw-mffw: os coeficientes do
//! polinômio saem de [1, 255] em vez de [0, 255]; sem correção publicada e sem manutenção). A
//! crate não foi trocada por uma versão "corrigida" de propósito: as shares já gravadas em
//! `security_questions.wrapped_share` foram geradas de forma DETERMINÍSTICA a partir da DEK, e
//! `share_for_index` recalcula novas shares ao adicionar perguntas. Uma shares nova precisa estar
//! no MESMO polinômio das antigas; mudar o sorteio dos coeficientes (como a correção do
//! advisory faz) criaria um segundo polinômio e uma recuperação que mistura shares antigas e
//! novas devolveria uma DEK errada. Por isso este módulo congela o "dealer v1" bit a bit.
//!
//! O que é compatível com `sharks` 0.5.0 (conferido por vetores gravados em `tests`, gerados
//! com a própria crate antes da remoção):
//! - corpo GF(2^8) com polinômio 0x11d e gerador 2;
//! - coeficientes de grau alto→baixo, sorteados com `Uniform::new_inclusive(1, 255)` do `rand`
//!   0.8 sobre o mesmo RNG, um polinômio por byte do segredo, em ordem;
//! - share = `[x, y_0, y_1, ...]`, avaliada em x = 1..=255;
//! - recuperação por interpolação de Lagrange em x = 0.
//!
//! A recuperação (a parte que o advisory diz NÃO ser afetada) não muda. O viés só enfraquece o
//! esquema quando o MESMO segredo é compartilhado centenas de vezes com polinômios
//! independentes; aqui o polinômio é derivado da DEK e é sempre o mesmo, então existe um único
//! polinômio por DEK (ver `docs/CREDENCIAIS_E_RECUPERACAO.md`).
//!
//! Novos formatos (ex.: um "dealer v2" com coeficientes em [0, 255]) exigem um marcador de
//! versão persistido e migração; não fazem parte desta mudança.

use rand::distributions::{Distribution, Uniform};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

const fn build_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    let mut j = 255;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = build_tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

/// `a / b`, com `b != 0` (garantido pelos chamadores).
fn gf_div(a: u8, b: u8) -> u8 {
    if a == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + 255 - LOG[b as usize] as usize]
    }
}

/// Uma share: `x` (1..=255) e um byte `y` por byte do segredo.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    x: u8,
    y: Vec<u8>,
}

impl Share {
    /// `[x, y_0, y_1, ...]`, o formato gravado (cifrado) no banco.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.y.len() + 1);
        bytes.push(self.x);
        bytes.extend_from_slice(&self.y);
        bytes
    }

    /// Recusa menos de 2 bytes e `x == 0` (o ponto x = 0 é o próprio segredo).
    pub fn from_bytes(bytes: &[u8]) -> Option<Share> {
        if bytes.len() < 2 || bytes[0] == 0 {
            return None;
        }
        Some(Share { x: bytes[0], y: bytes[1..].to_vec() })
    }
}

/// Dealer v1 (compatível com `sharks` 0.5.0): devolve a share de abscissa `x` (1..=255) do
/// `secret` com limiar `threshold`. O polinômio de cada byte tem `threshold - 1` coeficientes
/// aleatórios em [1, 255] (o viés do advisory, preservado de propósito) e o byte do segredo como
/// termo constante. Consome do `rng` exatamente o que o `sharks` consumia, independente de `x`.
pub fn deal_v1_share<R: Rng>(secret: &[u8], threshold: u8, x: u8, rng: &mut R) -> Option<Share> {
    if threshold == 0 || x == 0 {
        return None;
    }
    let between = Uniform::new_inclusive(1u8, 255u8);
    let y = secret
        .iter()
        .map(|&byte| {
            // Horner, do coeficiente de maior grau ao termo constante (= o byte do segredo).
            let mut poly = zeroize::Zeroizing::new(Vec::with_capacity(threshold as usize));
            for _ in 1..threshold {
                poly.push(between.sample(rng));
            }
            poly.push(byte);
            poly.iter().fold(0u8, |acc, &c| gf_mul(acc, x) ^ c)
        })
        .collect();
    Some(Share { x, y })
}

/// Recupera o segredo por interpolação de Lagrange em x = 0 usando TODAS as shares recebidas.
/// Recusa: menos de `threshold` shares, abscissas repetidas (corromperiam o resultado) e shares de
/// tamanhos diferentes.
pub fn recover(shares: &[Share], threshold: u8) -> Result<Vec<u8>, &'static str> {
    if threshold == 0 || shares.len() < threshold as usize {
        return Err("Not enough shares to recover original secret");
    }
    let len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != len) {
        return Err("All shares must have the same length");
    }
    for (i, a) in shares.iter().enumerate() {
        if shares[..i].iter().any(|b| b.x == a.x) {
            return Err("Duplicate share abscissa");
        }
    }
    Ok((0..len)
        .map(|byte| {
            shares.iter().fold(0u8, |acc, si| {
                let basis = shares
                    .iter()
                    .filter(|sj| sj.x != si.x)
                    .fold(1u8, |p, sj| gf_mul(p, gf_div(sj.x, sj.x ^ si.x)));
                acc ^ gf_mul(basis, si.y[byte])
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn deal(secret: &[u8], t: u8, x: u8, seed: u8) -> Share {
        deal_v1_share(secret, t, x, &mut ChaCha20Rng::from_seed([seed; 32])).unwrap()
    }

    /// Vetores gerados com `sharks` 0.5.0 (`dealer_rng`, ChaCha20, seed [0x5a; 32], limiar 3)
    /// ANTES de a crate ser removida. Se algum falhar, o dealer v1 deixou de ser compatível com as
    /// shares já gravadas em cofres existentes.
    #[test]
    fn dealer_v1_matches_vectors_generated_by_sharks_0_5_0() {
        let secret: Vec<u8> = (0u8..32).collect();
        let golden = [
            (1u8, "014c45a79ffa199e6349b0f9e663f9d5318fa840cf9e8000742c0fe600b577a648"),
            (2, "021d5a86c093c7209e49a20e3d9694d44b684f679d11341f01b4a2bc171d3f2356"),
            (3, "03511e235c6ddbb8fa081bfdd0f9600f75f7f635419ba1096280b4400cb4559b01"),
            (4, "0414dc7c27f2536671a175d984288f7e6791699bbe2e0f905c6a145aeb3ba63936"),
            (20, "14f30e1819a74c7cbff06a155f00be342f4326c42b7c74d34c4d19c239f890ce5c"),
            (255, "ff26b48d70917628d5c1734da5acafbf85dc99df67045d48738f5e1928f0802f03"),
        ];
        for (x, expected) in golden {
            assert_eq!(hex(&deal(&secret, 3, x, 0x5a).to_bytes()), expected, "x = {x}");
        }
    }

    #[test]
    fn field_tables_are_a_consistent_gf256() {
        // x * 1 = x, x * x^-1 = 1 e a divisão desfaz a multiplicação, para todos os elementos.
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_div(a, a), 1);
            for b in 1..=255u8 {
                assert_eq!(gf_div(gf_mul(a, b), b), a);
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
        // valores conhecidos de GF(2^8) com polinômio 0x11d
        assert_eq!(gf_mul(2, 0x80), 0x1d);
        assert_eq!(EXP[8], 0x1d);
    }

    #[test]
    fn any_subset_of_at_least_threshold_shares_recovers_the_secret() {
        let secret: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(53) ^ 0xa5).collect();
        let shares: Vec<Share> = (1..=8u8).map(|x| deal(&secret, 3, x, 9)).collect();
        for a in 0..8 {
            for b in a + 1..8 {
                for c in b + 1..8 {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(recover(&subset, 3).unwrap(), secret);
                }
            }
        }
        assert_eq!(recover(&shares, 3).unwrap(), secret);
    }

    #[test]
    fn fewer_than_threshold_shares_are_refused_and_do_not_reveal_the_secret() {
        let secret = [0x11u8; 32];
        let shares: Vec<Share> = (1..=2u8).map(|x| deal(&secret, 3, x, 4)).collect();
        assert!(recover(&shares, 3).is_err());
        assert!(recover(&[], 3).is_err());
        // Com limiar errado (2) a interpolação "funciona", mas devolve outro valor: não vaza o segredo.
        assert_ne!(recover(&shares, 2).unwrap(), secret.to_vec());
    }

    #[test]
    fn duplicate_abscissas_and_mismatched_lengths_are_refused() {
        let secret = [7u8; 32];
        let a = deal(&secret, 3, 1, 1);
        let b = deal(&secret, 3, 2, 1);
        assert!(recover(&[a.clone(), a.clone(), b.clone()], 3).is_err());
        let short = deal(&secret[..16], 3, 3, 1);
        assert!(recover(&[a, b, short], 3).is_err());
    }

    #[test]
    fn a_share_from_another_polynomial_corrupts_the_result_instead_of_being_trusted() {
        // É por isso que o dealer não pode mudar de polinômio para cofres existentes.
        let secret = [0x42u8; 32];
        let a = deal(&secret, 3, 1, 1);
        let b = deal(&secret, 3, 2, 1);
        let foreign = deal(&secret, 3, 3, 2);
        assert_ne!(recover(&[a, b, foreign], 3).unwrap(), secret.to_vec());
    }

    #[test]
    fn share_bytes_roundtrip_and_malformed_bytes_are_refused() {
        let share = deal(&[1, 2, 3], 3, 9, 3);
        let bytes = share.to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], 9);
        assert_eq!(Share::from_bytes(&bytes).unwrap().to_bytes(), bytes);
        assert!(Share::from_bytes(&[]).is_none());
        assert!(Share::from_bytes(&[5]).is_none());
        assert!(Share::from_bytes(&[0, 1, 2]).is_none());
    }

    #[test]
    fn dealer_rejects_degenerate_parameters() {
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        assert!(deal_v1_share(&[1], 0, 1, &mut rng).is_none());
        assert!(deal_v1_share(&[1], 3, 0, &mut rng).is_none());
    }

    #[test]
    fn dealer_is_deterministic_and_independent_of_the_requested_index() {
        let secret = [0x33u8; 32];
        assert_eq!(deal(&secret, 3, 5, 8).to_bytes(), deal(&secret, 3, 5, 8).to_bytes());
        assert_ne!(deal(&secret, 3, 5, 8).to_bytes(), deal(&secret, 3, 5, 9).to_bytes());
    }
}
