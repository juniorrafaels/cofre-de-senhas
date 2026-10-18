use rand::seq::SliceRandom;
use rand::Rng;
use serde::Deserialize;
use std::collections::HashMap;

const MIN_LENGTH: u32 = 4;
const MAX_LENGTH: u32 = 128;

const DIGITS: &str = "0123456789";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
// Conjunto deliberadamente sem aspas/backtick/barra invertida — evita símbolos que costumam
// causar problema em copiar/colar em terminais ou formulários, sem reduzir a entropia de forma
// perceptível (ainda são 22 símbolos).
const SPECIAL: &str = "!@#$%^&*()-_=+[]{}<>?";

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CharClass {
    Numbers,
    Upper,
    Lower,
    Special,
}

impl CharClass {
    const ALL: [CharClass; 4] = [CharClass::Numbers, CharClass::Upper, CharClass::Lower, CharClass::Special];

    fn alphabet(&self) -> &'static str {
        match self {
            CharClass::Numbers => DIGITS,
            CharClass::Upper => UPPER,
            CharClass::Lower => LOWER,
            CharClass::Special => SPECIAL,
        }
    }
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CountMode {
    Auto,
    Fixed,
}

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClassOptions {
    pub enabled: bool,
    pub mode: CountMode,
    pub count: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PasswordGeneratorOptions {
    pub length: u32,
    pub numbers: ClassOptions,
    pub upper: ClassOptions,
    pub lower: ClassOptions,
    pub special: ClassOptions,
    pub start_type: Option<CharClass>,
    pub end_type: Option<CharClass>,
    pub avoid_sequences: bool,
}

fn class_options(class: CharClass, opts: &PasswordGeneratorOptions) -> &ClassOptions {
    match class {
        CharClass::Numbers => &opts.numbers,
        CharClass::Upper => &opts.upper,
        CharClass::Lower => &opts.lower,
        CharClass::Special => &opts.special,
    }
}

/// Calcula quantos caracteres de cada tipo habilitado a senha final vai conter, sem gerar nada
/// ainda. Erros aqui são exatamente as validações pedidas na seção 3.3 (soma das quantidades
/// definidas não pode ultrapassar o tamanho total) e 3.5 (começo/fim precisam de pelo menos 1
/// caractere reservado do tipo escolhido).
fn plan_counts(options: &PasswordGeneratorOptions) -> Result<HashMap<CharClass, usize>, String> {
    let length = options.length as usize;

    let enabled: Vec<CharClass> = CharClass::ALL.into_iter().filter(|c| class_options(*c, options).enabled).collect();
    if enabled.is_empty() {
        return Err("Selecione ao menos um tipo de caractere.".to_string());
    }

    let mut counts: HashMap<CharClass, usize> = HashMap::new();
    let mut fixed_sum: usize = 0;
    let mut auto_classes: Vec<CharClass> = Vec::new();
    for class in &enabled {
        let opts = class_options(*class, options);
        if opts.mode == CountMode::Fixed {
            let count = opts.count as usize;
            if count > length {
                return Err("A quantidade definida para um tipo não pode ser maior que o tamanho da senha.".to_string());
            }
            counts.insert(*class, count);
            fixed_sum += count;
        } else {
            auto_classes.push(*class);
        }
    }
    if fixed_sum > length {
        return Err("A soma das quantidades definidas não pode ultrapassar o tamanho total da senha.".to_string());
    }

    let remaining = length - fixed_sum;
    if auto_classes.is_empty() {
        // Nenhum tipo em automático para absorver o restante: distribui entre todos os tipos
        // habilitados (round-robin) para que a soma final bata exatamente com o tamanho pedido.
        let mut left = remaining;
        let mut idx = 0;
        while left > 0 {
            let class = enabled[idx % enabled.len()];
            *counts.get_mut(&class).unwrap() += 1;
            left -= 1;
            idx += 1;
        }
    } else {
        let base = remaining / auto_classes.len();
        let mut extra = remaining % auto_classes.len();
        for class in &auto_classes {
            let mut n = base;
            if extra > 0 {
                n += 1;
                extra -= 1;
            }
            counts.insert(*class, n);
        }
    }

    if let Some(start) = options.start_type {
        if !enabled.contains(&start) {
            return Err("O tipo escolhido para começar a senha precisa estar habilitado.".to_string());
        }
        if counts.get(&start).copied().unwrap_or(0) == 0 {
            return Err("O tipo escolhido para começar a senha precisa ter ao menos 1 caractere reservado.".to_string());
        }
    }
    if let Some(end) = options.end_type {
        if !enabled.contains(&end) {
            return Err("O tipo escolhido para terminar a senha precisa estar habilitado.".to_string());
        }
        if counts.get(&end).copied().unwrap_or(0) == 0 {
            return Err("O tipo escolhido para terminar a senha precisa ter ao menos 1 caractere reservado.".to_string());
        }
    }
    if let (Some(start), Some(end)) = (options.start_type, options.end_type) {
        if start == end && length > 1 && counts.get(&start).copied().unwrap_or(0) < 2 {
            return Err(
                "Para começar e terminar com o mesmo tipo, reserve pelo menos 2 caracteres dele.".to_string(),
            );
        }
    }

    let total: usize = counts.values().sum();
    if total != length {
        return Err("Falha ao distribuir os caracteres da senha.".to_string());
    }

    Ok(counts)
}

fn random_char(alphabet: &str, rng: &mut impl Rng) -> char {
    let chars: Vec<char> = alphabet.chars().collect();
    chars[rng.gen_range(0..chars.len())]
}

/// Monta uma senha candidata a partir do plano de quantidades já validado, usando o CSPRNG do SO
/// (`OsRng`, via `rand::Rng`/`rand::seq::SliceRandom` — nunca um PRNG comum) tanto para escolher
/// cada caractere dentro do alfabeto do seu tipo quanto para embaralhar as posições do meio.
fn build_candidate(counts: &HashMap<CharClass, usize>, start: Option<CharClass>, end: Option<CharClass>, length: usize) -> String {
    let mut rng = rand::rngs::OsRng;

    if length == 1 {
        let class = start.or(end).unwrap_or_else(|| *counts.iter().find(|(_, &n)| n > 0).unwrap().0);
        return random_char(class.alphabet(), &mut rng).to_string();
    }

    let mut remaining = counts.clone();
    let start_char = start.map(|class| {
        *remaining.get_mut(&class).unwrap() -= 1;
        random_char(class.alphabet(), &mut rng)
    });
    let end_char = end.map(|class| {
        *remaining.get_mut(&class).unwrap() -= 1;
        random_char(class.alphabet(), &mut rng)
    });

    let mut pool: Vec<char> = Vec::with_capacity(length);
    for (class, n) in remaining.iter() {
        for _ in 0..*n {
            pool.push(random_char(class.alphabet(), &mut rng));
        }
    }
    pool.shuffle(&mut rng);

    let mut result: Vec<char> = Vec::with_capacity(length);
    if let Some(c) = start_char {
        result.push(c);
    }
    result.extend(pool);
    if let Some(c) = end_char {
        result.push(c);
    }
    result.into_iter().collect()
}

fn sequence_class(c: char) -> Option<u8> {
    if c.is_ascii_digit() {
        Some(0)
    } else if c.is_ascii_lowercase() {
        Some(1)
    } else if c.is_ascii_uppercase() {
        Some(2)
    } else {
        None
    }
}

/// Detecta sequências óbvias de 3 caracteres consecutivos (crescentes ou decrescentes) dentro da
/// mesma classe — dígitos, minúsculas ou maiúsculas — como `123`, `abc`, `ABC`, `321`, `cba`.
/// Não é uma análise de entropia; é deliberadamente simples, como pedido na seção 3.6.
fn has_trivial_sequence(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return false;
    }
    for i in 0..=chars.len() - 3 {
        let (a, b, c) = (chars[i], chars[i + 1], chars[i + 2]);
        let classes = (sequence_class(a), sequence_class(b), sequence_class(c));
        let (Some(ca), Some(cb), Some(cc)) = classes else { continue };
        if ca != cb || cb != cc {
            continue;
        }
        let (a, b, c) = (a as i32, b as i32, c as i32);
        if b == a + 1 && c == b + 1 {
            return true;
        }
        if b == a - 1 && c == b - 1 {
            return true;
        }
    }
    false
}

const MAX_SEQUENCE_RETRY_ATTEMPTS: usize = 40;

/// Gera uma senha respeitando as regras configuradas na UI (Configurações → Gerador de Senhas).
/// Roda inteiramente no backend usando `OsRng` (CSPRNG do sistema operacional) — nunca
/// `Math.random()` ou qualquer PRNG não seguro no frontend. Não grava nada no banco, não loga o
/// resultado e não é chamado por nenhum outro command: a senha só existe na resposta desta
/// chamada e no estado React que a exibe, até o usuário gerar outra ou fechar a tela.
#[tauri::command]
pub fn generate_password(options: PasswordGeneratorOptions) -> Result<String, String> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&options.length) {
        return Err(format!("O tamanho da senha deve estar entre {MIN_LENGTH} e {MAX_LENGTH} caracteres."));
    }
    let length = options.length as usize;
    let counts = plan_counts(&options)?;

    let mut candidate = String::new();
    for _ in 0..MAX_SEQUENCE_RETRY_ATTEMPTS {
        candidate = build_candidate(&counts, options.start_type, options.end_type, length);
        if !options.avoid_sequences || !has_trivial_sequence(&candidate) {
            return Ok(candidate);
        }
    }
    // Melhor esforço: depois de várias tentativas, aceita o último candidato em vez de travar —
    // a seção 3.6 pede para evitar sequências triviais, não garanti-las matematicamente.
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled() -> ClassOptions {
        ClassOptions { enabled: false, mode: CountMode::Auto, count: 0 }
    }

    fn auto() -> ClassOptions {
        ClassOptions { enabled: true, mode: CountMode::Auto, count: 0 }
    }

    fn fixed(count: u32) -> ClassOptions {
        ClassOptions { enabled: true, mode: CountMode::Fixed, count }
    }

    fn base_options(length: u32) -> PasswordGeneratorOptions {
        PasswordGeneratorOptions {
            length,
            numbers: disabled(),
            upper: disabled(),
            lower: disabled(),
            special: disabled(),
            start_type: None,
            end_type: None,
            avoid_sequences: false,
        }
    }

    // Regressão de contrato: garante que o JSON exatamente no formato que o frontend envia
    // (camelCase, `startType`/`endType` como string ou null) desserializa como esperado — sem
    // isso, um erro de nome de campo só apareceria em tempo de execução dentro do app de verdade.
    #[test]
    fn deserializes_frontend_shaped_json() {
        let json = r#"{
            "length": 14,
            "numbers": { "enabled": true, "mode": "auto", "count": 0 },
            "upper": { "enabled": true, "mode": "fixed", "count": 3 },
            "lower": { "enabled": true, "mode": "auto", "count": 0 },
            "special": { "enabled": false, "mode": "auto", "count": 0 },
            "startType": "upper",
            "endType": null,
            "avoidSequences": true
        }"#;
        let opts: PasswordGeneratorOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.length, 14);
        assert!(opts.numbers.enabled);
        assert_eq!(opts.upper.mode, CountMode::Fixed);
        assert_eq!(opts.upper.count, 3);
        assert!(!opts.special.enabled);
        assert_eq!(opts.start_type, Some(CharClass::Upper));
        assert_eq!(opts.end_type, None);
        assert!(opts.avoid_sequences);

        let password = generate_password(opts).unwrap();
        assert_eq!(password.chars().count(), 14);
        assert!(password.chars().next().unwrap().is_ascii_uppercase());
    }

    #[test]
    fn generated_password_has_the_requested_length() {
        let mut opts = base_options(16);
        opts.lower = auto();
        opts.numbers = auto();
        let password = generate_password(opts).unwrap();
        assert_eq!(password.chars().count(), 16);
    }

    #[test]
    fn only_numbers_uses_only_digits() {
        let mut opts = base_options(20);
        opts.numbers = auto();
        let password = generate_password(opts).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn only_upper_uses_only_uppercase_letters() {
        let mut opts = base_options(20);
        opts.upper = auto();
        let password = generate_password(opts).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn only_lower_uses_only_lowercase_letters() {
        let mut opts = base_options(20);
        opts.lower = auto();
        let password = generate_password(opts).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn only_special_uses_only_special_characters() {
        let mut opts = base_options(20);
        opts.special = auto();
        let password = generate_password(opts).unwrap();
        assert!(password.chars().all(|c| SPECIAL.contains(c)));
    }

    #[test]
    fn mixing_all_types_uses_only_the_combined_alphabet() {
        let mut opts = base_options(40);
        opts.numbers = auto();
        opts.upper = auto();
        opts.lower = auto();
        opts.special = auto();
        let password = generate_password(opts).unwrap();
        let full_alphabet: String = format!("{DIGITS}{UPPER}{LOWER}{SPECIAL}");
        assert!(password.chars().all(|c| full_alphabet.contains(c)));
    }

    #[test]
    fn exact_fixed_counts_are_respected() {
        let mut opts = base_options(12);
        opts.numbers = fixed(4);
        opts.upper = fixed(3);
        opts.lower = fixed(5);
        let password = generate_password(opts).unwrap();
        assert_eq!(password.chars().count(), 12);
        assert_eq!(password.chars().filter(|c| c.is_ascii_digit()).count(), 4);
        assert_eq!(password.chars().filter(|c| c.is_ascii_uppercase()).count(), 3);
        assert_eq!(password.chars().filter(|c| c.is_ascii_lowercase()).count(), 5);
    }

    // Seção 3.3: 5 + 5 + 5 = 15 > 12 deve ser rejeitado.
    #[test]
    fn sum_of_fixed_counts_exceeding_length_is_rejected() {
        let mut opts = base_options(12);
        opts.numbers = fixed(5);
        opts.upper = fixed(5);
        opts.special = fixed(5);
        assert!(generate_password(opts).is_err());
    }

    #[test]
    fn required_start_type_is_honored() {
        let mut opts = base_options(10);
        opts.numbers = auto();
        opts.upper = auto();
        opts.start_type = Some(CharClass::Numbers);
        let password = generate_password(opts).unwrap();
        assert!(password.chars().next().unwrap().is_ascii_digit());
    }

    #[test]
    fn required_end_type_is_honored() {
        let mut opts = base_options(10);
        opts.numbers = auto();
        opts.upper = auto();
        opts.end_type = Some(CharClass::Upper);
        let password = generate_password(opts).unwrap();
        assert!(password.chars().last().unwrap().is_ascii_uppercase());
    }

    #[test]
    fn start_and_end_can_be_set_simultaneously_with_different_types() {
        let mut opts = base_options(10);
        opts.numbers = auto();
        opts.upper = auto();
        opts.start_type = Some(CharClass::Upper);
        opts.end_type = Some(CharClass::Numbers);
        let password = generate_password(opts).unwrap();
        assert!(password.chars().next().unwrap().is_ascii_uppercase());
        assert!(password.chars().last().unwrap().is_ascii_digit());
    }

    // Seção 3.4/3.5: começar e terminar com o MESMO tipo só é possível se houver pelo menos 2
    // caracteres reservados dele.
    #[test]
    fn same_start_and_end_type_requires_at_least_two_reserved_characters() {
        let mut opts = base_options(10);
        opts.numbers = fixed(1);
        opts.upper = auto();
        opts.start_type = Some(CharClass::Numbers);
        opts.end_type = Some(CharClass::Numbers);
        assert!(generate_password(opts).is_err());

        let mut opts_ok = base_options(10);
        opts_ok.numbers = fixed(2);
        opts_ok.upper = auto();
        opts_ok.start_type = Some(CharClass::Numbers);
        opts_ok.end_type = Some(CharClass::Numbers);
        let password = generate_password(opts_ok).unwrap();
        assert!(password.chars().next().unwrap().is_ascii_digit());
        assert!(password.chars().last().unwrap().is_ascii_digit());
    }

    // Seção 3.5: não pode escolher "começar com" um tipo cuja quantidade definida é 0.
    #[test]
    fn start_type_with_zero_reserved_characters_is_rejected() {
        let mut opts = base_options(10);
        opts.numbers = fixed(0);
        opts.upper = auto();
        opts.start_type = Some(CharClass::Numbers);
        assert!(generate_password(opts).is_err());
    }

    // A UI só permite um único valor em "começar com"/"terminar com" (campo único, não múltiplas
    // caixas de seleção) — a própria estrutura de dados já impede que dois tipos comecem ou
    // terminem a senha ao mesmo tempo, então não existe combinação inválida desse tipo para testar.
    #[test]
    fn avoid_sequences_prevents_trivial_ascending_and_descending_runs() {
        assert!(has_trivial_sequence("a1b2c123d"));
        assert!(has_trivial_sequence("xxxABCyyy"));
        assert!(has_trivial_sequence("xxx321yyy"));
        assert!(has_trivial_sequence("xxxcbayyy"));
        assert!(!has_trivial_sequence("a1c3e5g7i9"));

        let mut opts = base_options(30);
        opts.numbers = auto();
        opts.lower = auto();
        opts.upper = auto();
        opts.avoid_sequences = true;
        let password = generate_password(opts).unwrap();
        assert!(!has_trivial_sequence(&password), "senha gerada com avoid_sequences não deveria conter sequência: {password}");
    }

    #[test]
    fn rejects_length_outside_allowed_bounds() {
        let mut too_short = base_options(3);
        too_short.numbers = auto();
        assert!(generate_password(too_short).is_err());

        let mut too_long = base_options(129);
        too_long.numbers = auto();
        assert!(generate_password(too_long).is_err());
    }

    #[test]
    fn rejects_when_no_character_type_is_enabled() {
        let opts = base_options(10);
        assert!(generate_password(opts).is_err());
    }

    // Regressão de segurança: duas gerações consecutivas com os mesmos parâmetros não podem
    // colidir — um sinal básico de que a fonte de aleatoriedade (OsRng) está realmente sendo
    // usada, e não algo determinístico.
    #[test]
    fn consecutive_generations_do_not_collide() {
        let mut opts = base_options(24);
        opts.numbers = auto();
        opts.upper = auto();
        opts.lower = auto();
        opts.special = auto();
        let a = generate_password(opts).unwrap();
        let mut opts2 = base_options(24);
        opts2.numbers = auto();
        opts2.upper = auto();
        opts2.lower = auto();
        opts2.special = auto();
        let b = generate_password(opts2).unwrap();
        assert_ne!(a, b);
    }
}
