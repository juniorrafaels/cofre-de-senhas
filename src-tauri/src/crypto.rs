use argon2::{Argon2, Params, Version, Algorithm};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, Key,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("senha incorreta ou dados corrompidos")]
    DecryptionFailed,
    #[error("falha interna de criptografia")]
    Internal,
    #[error("parâmetros de derivação de chave fora dos limites aceitos")]
    InvalidKdfParams,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // ~128 MiB, 3 iterations, 1 lane — alvo de ~300-500ms em hardware desktop comum.
        Self { memory_kib: 128 * 1024, iterations: 3, parallelism: 1 }
    }
}

/// Limites aceitos para parâmetros do Argon2id lidos de fontes não confiáveis (cabeçalho de
/// arquivo de backup, `vault_meta`, Recovery Key, perguntas de segurança). Sem esse teto, um
/// arquivo de backup forjado poderia pedir, por exemplo, `memory_kib = 4 GiB` ou milhões de
/// iterações e travar/derrubar o app (DoS por alocação/CPU) antes mesmo de a senha ser checada.
/// O piso evita que um banco adulterado rebaixe o custo do KDF para valores triviais.
/// `KdfParams::default()` (128 MiB, t=3, p=1) e os parâmetros de teste (8 MiB, t=1, p=1) ficam
/// dentro destes limites.
pub const KDF_MIN_MEMORY_KIB: u32 = 8 * 1024;
pub const KDF_MAX_MEMORY_KIB: u32 = 1024 * 1024;
pub const KDF_MAX_ITERATIONS: u32 = 20;
pub const KDF_MAX_PARALLELISM: u32 = 16;

impl KdfParams {
    /// `true` se os parâmetros estão dentro dos limites aceitos (ver constantes `KDF_*`).
    pub fn is_within_bounds(&self) -> bool {
        (KDF_MIN_MEMORY_KIB..=KDF_MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (1..=KDF_MAX_ITERATIONS).contains(&self.iterations)
            && (1..=KDF_MAX_PARALLELISM).contains(&self.parallelism)
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Deriva uma chave de 32 bytes da senha mestra usando Argon2id.
pub fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    // Validação ANTES de chamar o Argon2: parâmetros fora dos limites nunca chegam a alocar
    // memória nem a gastar CPU (ver `KdfParams::is_within_bounds`).
    if !params.is_within_bounds() {
        return Err(CryptoError::InvalidKdfParams);
    }
    let argon2_params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_LEN))
        .map_err(|_| CryptoError::Internal)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::Internal)?;
    Ok(out)
}

/// Cifra `plaintext` com a chave dada. Retorna `nonce || ciphertext (com tag)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = random_bytes(NONCE_LEN);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Internal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Deriva, de forma determinística, uma seed de 32 bytes a partir da DEK e de um contexto.
/// Usada para reconstruir o "dealer" do Shamir Secret Sharing sob demanda (mesma DEK + mesmo
/// contexto sempre gera a mesma seed, então cada share pode ser recalculada quando necessário
/// sem precisar armazenar o polinômio ou reunir respostas antigas).
pub fn derive_deterministic_seed(dek: &[u8; KEY_LEN], context: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, dek);
    let mut seed = [0u8; 32];
    hk.expand(context, &mut seed).expect("comprimento de seed válido");
    seed
}

/// Decifra um blob no formato `nonce || ciphertext (com tag)`.
pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Cifra um texto puro e o codifica em base64 — formato usado para todo campo cifrado gravado no
/// SQLite (`nonce || ciphertext+tag`, depois base64). Usado pelos commands específicos por ação
/// (Fase 4 — ver SECURITY_AUDIT_PHASE_4.md) para que cada um cifre internamente, em vez de a
/// WebView chamar um `encrypt_secret` genérico e gravar o ciphertext resultante.
pub fn encrypt_to_base64(key: &[u8; KEY_LEN], plaintext: &str) -> Result<String, String> {
    encrypt(key, plaintext.as_bytes())
        .map(|bytes| B64.encode(bytes))
        .map_err(|_| "Falha ao criptografar.".to_string())
}

/// Decifra um campo gravado em base64 e devolve o texto puro. Contraparte de
/// `encrypt_to_base64`, usada pelos commands de "revelar"/"copiar" por ID (nunca recebem
/// ciphertext da WebView — sempre buscam a coluna eles mesmos antes de chamar esta função).
pub fn decrypt_from_base64(key: &[u8; KEY_LEN], ciphertext: &str) -> Result<String, String> {
    let bytes = B64.decode(ciphertext).map_err(|_| "Dados inválidos.".to_string())?;
    decrypt(key, &bytes)
        .map(|plain| String::from_utf8_lossy(&plain).to_string())
        .map_err(|_| "Falha ao descriptografar.".to_string())
}

// ---------------------------------------------------------------------------------------------
// Campos de metadados com formato versionado e AAD (`enc:v2:`)
// ---------------------------------------------------------------------------------------------
//
// Diferente do formato legado de `encrypt_to_base64` (usado por senha, notas e 2FA: base64 puro,
// sem AAD), os campos de metadados (`accounts.name/username/email/category/login_url/
// website_url`, `account_history.detail`) gravam `enc:v2:` + base64(nonce || ciphertext+tag) e
// autenticam um AAD que amarra o valor à sua tabela, coluna e linha. Copiar o ciphertext para
// outra conta, outra coluna ou outra tabela faz o AEAD falhar — o valor nunca é "trocado em
// silêncio". A autenticidade vem da tag Poly1305, não do prefixo (o prefixo só diz qual formato
// tentar). As colunas legadas de segredo continuam no formato antigo: cada coluna tem um formato
// fixo, então não há ambiguidade entre os dois.

pub const FIELD_PREFIX_V2: &str = "enc:v2:";
const FIELD_AAD_CONTEXT: &[u8] = b"cofre/field/v2";

/// Motivo pelo qual um campo não pôde ser lido. Nunca carrega o valor.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FieldError {
    /// Prefixo `enc:vN:` com N desconhecido (cofre de uma versão mais nova do app).
    UnknownVersion,
    /// Falha de autenticação (adulterado, copiado de outro campo/linha, chave errada) ou base64/UTF-8 inválido.
    Corrupt,
}

/// AAD sem ambiguidade: cada parte textual vem com prefixo de tamanho (u32 BE) e o id da linha
/// entra como i64 BE de largura fixa — `("a","bc")` nunca colide com `("ab","c")`.
pub fn field_aad(table: &str, column: &str, row_id: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FIELD_AAD_CONTEXT.len() + table.len() + column.len() + 16);
    for part in [FIELD_AAD_CONTEXT, table.as_bytes(), column.as_bytes()] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&row_id.to_be_bytes());
    aad
}

/// Como `encrypt`, mas autenticando `aad`. Nonce de 24 bytes aleatório do SO a cada chamada.
pub fn encrypt_aad(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = random_bytes(NONCE_LEN);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Internal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Contraparte de `encrypt_aad`: falha se a chave, o AAD ou qualquer byte do ciphertext diferir.
pub fn decrypt_aad(key: &[u8; KEY_LEN], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_LEN {
        return Err(CryptoError::DecryptionFailed);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), chacha20poly1305::aead::Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// `true` se o valor armazenado tem a forma `enc:v<dígitos>:` (qualquer versão).
pub fn has_field_version_prefix(stored: &str) -> bool {
    match stored.strip_prefix("enc:v") {
        Some(rest) => {
            let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
            digits > 0 && rest[digits..].starts_with(':')
        }
        None => false,
    }
}

/// Cifra um campo de metadado no formato `enc:v2:`. `row_id` é o id estável da linha.
pub fn encrypt_field(key: &[u8; KEY_LEN], table: &str, column: &str, row_id: i64, plaintext: &str) -> Result<String, String> {
    encrypt_aad(key, plaintext.as_bytes(), &field_aad(table, column, row_id))
        .map(|bytes| format!("{FIELD_PREFIX_V2}{}", B64.encode(bytes)))
        .map_err(|_| "Falha ao criptografar.".to_string())
}

/// Lê um campo de metadado. Valor sem prefixo `enc:vN:` = texto puro LEGADO (cofre ainda não
/// migrado), devolvido como está para permitir abrir cofres antigos. `enc:v2:` é verificado com
/// o AAD de (tabela, coluna, linha). Outras versões ou falhas viram `FieldError` — nunca um
/// valor vazio ou "quase certo".
pub fn decrypt_field(key: &[u8; KEY_LEN], table: &str, column: &str, row_id: i64, stored: &str) -> Result<String, FieldError> {
    if let Some(b64) = stored.strip_prefix(FIELD_PREFIX_V2) {
        let bytes = B64.decode(b64).map_err(|_| FieldError::Corrupt)?;
        let plain = decrypt_aad(key, &bytes, &field_aad(table, column, row_id)).map_err(|_| FieldError::Corrupt)?;
        return String::from_utf8(plain.to_vec()).map_err(|_| FieldError::Corrupt);
    }
    if has_field_version_prefix(stored) {
        return Err(FieldError::UnknownVersion);
    }
    Ok(stored.to_string())
}

// Alfabeto Crockford Base32 (32 símbolos = exatamente 5 bits/caractere, sem viés de módulo,
// e sem os caracteres ambíguos 0/O, 1/I/L que atrapalham cópia manual/impressão).
const RECOVERY_KEY_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const RECOVERY_KEY_SYMBOLS: usize = 24; // 24 * 5 bits = 120 bits de entropia
const RECOVERY_KEY_ENTROPY_BYTES: usize = 15; // 120 bits

/// Gera uma Recovery Key aleatória de alta entropia (120 bits), formatada em grupos de 4
/// separados por hífen (ex.: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`) para facilitar cópia/impressão.
/// Não usa Argon2/senha nenhuma — é puro material aleatório do SO (`OsRng`), ao contrário das
/// perguntas de segurança, cuja entropia depende do usuário.
pub fn generate_recovery_key() -> String {
    let bytes = random_bytes(RECOVERY_KEY_ENTROPY_BYTES);
    let mut symbols = Vec::with_capacity(RECOVERY_KEY_SYMBOLS);
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u32 = 0;
    for byte in &bytes {
        bit_buffer = (bit_buffer << 8) | (*byte as u32);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bit_buffer >> bit_count) & 0b1_1111) as usize;
            symbols.push(RECOVERY_KEY_ALPHABET[idx]);
        }
    }
    symbols
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Normaliza a Recovery Key digitada pelo usuário (remove hífens/espaços, força maiúsculas)
/// antes de usá-la como entrada da derivação de chave — mesma ideia de `normalize_answer` para
/// perguntas de segurança, mas aqui só para tolerar formatação, não para compensar baixa entropia.
pub fn normalize_recovery_key(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_uppercase()
}

/// SHA-256 de `data` em hexadecimal minúsculo (64 caracteres). Os nomes das imagens e o hash de
/// reparo do logotipo dependem deste formato exato.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_lowercase_and_matches_the_standard_vectors() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    // Testes de regressão de segurança (SECURITY_AUDIT.md, seção 5 e 30): validam as
    // propriedades criptográficas de que a auditoria depende — nenhuma senha/segredo em
    // texto puro sobrevive à cifragem, adulteração é detectada, e a chave errada nunca decifra.

    fn test_params() -> KdfParams {
        // Parâmetros reduzidos apenas para o teste rodar rápido; produção usa KdfParams::default().
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let salt = random_bytes(SALT_LEN);
        let key = derive_key("senha-mestra-de-teste", &salt, &test_params()).unwrap();
        let plaintext = b"TEST_PASSWORD_SECURITY_948217";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn ciphertext_never_contains_plaintext_secret() {
        let salt = random_bytes(SALT_LEN);
        let key = derive_key("senha-mestra-de-teste", &salt, &test_params()).unwrap();
        let secret = b"TEST_API_KEY_SECURITY_172839";

        let ciphertext = encrypt(&key, secret).unwrap();

        // O ciphertext bruto (o que de fato é gravado no SQLite) não pode conter o segredo em
        // texto puro nem em nenhuma janela de bytes dele.
        assert!(!ciphertext.windows(secret.len()).any(|w| w == secret.as_slice()));
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let salt = random_bytes(SALT_LEN);
        let key = derive_key("senha-mestra-de-teste", &salt, &test_params()).unwrap();
        let mut ciphertext = encrypt(&key, b"dado sensivel").unwrap();

        // Adultera um byte do ciphertext (após o nonce) — o AEAD deve rejeitar por falha de tag.
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;

        assert!(decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let salt = random_bytes(SALT_LEN);
        let params = test_params();
        let right_key = derive_key("senha-correta", &salt, &params).unwrap();
        let wrong_key = derive_key("senha-errada", &salt, &params).unwrap();

        let ciphertext = encrypt(&right_key, b"segredo do cofre").unwrap();

        assert!(decrypt(&wrong_key, &ciphertext).is_err());
    }

    #[test]
    fn same_password_and_salt_derive_same_key_different_salt_differs() {
        let salt_a = random_bytes(SALT_LEN);
        let salt_b = random_bytes(SALT_LEN);
        let params = test_params();

        let key_a1 = derive_key("mesma-senha", &salt_a, &params).unwrap();
        let key_a2 = derive_key("mesma-senha", &salt_a, &params).unwrap();
        let key_b = derive_key("mesma-senha", &salt_b, &params).unwrap();

        assert_eq!(*key_a1, *key_a2);
        assert_ne!(*key_a1, *key_b);
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let salt = random_bytes(SALT_LEN);
        let key = derive_key("senha", &salt, &test_params()).unwrap();

        let ciphertext_1 = encrypt(&key, b"mesmo texto").unwrap();
        let ciphertext_2 = encrypt(&key, b"mesmo texto").unwrap();

        // Mesma chave e mesmo plaintext, mas nonces aleatórios distintos: o ciphertext (que
        // inclui o nonce) não pode se repetir entre chamadas.
        assert_ne!(ciphertext_1, ciphertext_2);
    }

    #[test]
    fn default_and_test_kdf_params_are_within_bounds() {
        assert!(KdfParams::default().is_within_bounds());
        assert!(test_params().is_within_bounds());
    }

    #[test]
    fn excessive_or_trivial_kdf_params_are_rejected_before_running_argon2() {
        let salt = random_bytes(SALT_LEN);
        let bad = [
            KdfParams { memory_kib: u32::MAX, iterations: 1, parallelism: 1 },
            KdfParams { memory_kib: KDF_MAX_MEMORY_KIB + 1, iterations: 1, parallelism: 1 },
            KdfParams { memory_kib: 8 * 1024, iterations: 1_000_000, parallelism: 1 },
            KdfParams { memory_kib: 8 * 1024, iterations: 0, parallelism: 1 },
            KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 0 },
            KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 255 },
            KdfParams { memory_kib: 1, iterations: 1, parallelism: 1 },
        ];
        let started = std::time::Instant::now();
        for params in bad {
            assert!(!params.is_within_bounds());
            assert!(matches!(derive_key("senha", &salt, &params), Err(CryptoError::InvalidKdfParams)));
        }
        // Nenhuma chamada chegou a rodar o Argon2 (seriam GiBs de RAM / milhões de passes).
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn recovery_key_has_expected_shape_and_entropy() {
        let key = generate_recovery_key();
        let normalized = normalize_recovery_key(&key);

        assert_eq!(normalized.len(), RECOVERY_KEY_SYMBOLS);
        assert!(normalized.chars().all(|c| RECOVERY_KEY_ALPHABET.contains(&(c as u8))));
        assert_eq!(key.matches('-').count(), 5); // 24 símbolos em grupos de 4 => 5 hífens

        // Duas chamadas não podem colidir (seria um sinal de RNG quebrado, não uma prova de
        // entropia, mas uma colisão aqui indicaria um bug grave).
        assert_ne!(generate_recovery_key(), generate_recovery_key());
    }

    #[test]
    fn normalize_recovery_key_tolerates_formatting() {
        let raw = "abcd-2345-hjkm";
        let normalized = normalize_recovery_key(raw);
        assert_eq!(normalized, "ABCD2345HJKM");

        // Com ou sem hífens/espaços/caixa, a chave normalizada deve ser idêntica.
        assert_eq!(normalize_recovery_key("ABCD 2345 HJKM"), normalized);
        assert_eq!(normalize_recovery_key("abcd2345hjkm"), normalized);
    }

    #[test]
    fn recovery_key_can_wrap_and_unwrap_a_dek_like_a_password() {
        // A Recovery Key não inventa criptografia nova: usa exatamente o mesmo par
        // derive_key + encrypt/decrypt já usado para a senha mestra.
        let recovery_key = generate_recovery_key();
        let normalized = normalize_recovery_key(&recovery_key);
        let salt = random_bytes(SALT_LEN);
        let params = test_params();

        let kek2 = derive_key(&normalized, &salt, &params).unwrap();
        let dek = [42u8; KEY_LEN];
        let wrapped = encrypt(&kek2, &dek).unwrap();

        let recovered = decrypt(&kek2, &wrapped).unwrap();
        assert_eq!(recovered.as_slice(), &dek);

        // Digitar a chave errada (mesmo só 1 símbolo diferente) não pode desembrulhar a DEK.
        let mut tampered = normalized.clone();
        let last_char = tampered.pop().unwrap();
        let replacement = if last_char == '0' { '1' } else { '0' };
        tampered.push(replacement);
        let wrong_kek2 = derive_key(&tampered, &salt, &params).unwrap();
        assert!(decrypt(&wrong_kek2, &wrapped).is_err());
    }

    // ---- Campos `enc:v2:` com AAD ----

    #[test]
    fn field_round_trip_and_nonce_is_fresh_each_time() {
        let key = [4u8; KEY_LEN];
        let a = encrypt_field(&key, "accounts", "username", 7, "audit-user-7391").unwrap();
        let b = encrypt_field(&key, "accounts", "username", 7, "audit-user-7391").unwrap();
        assert!(a.starts_with(FIELD_PREFIX_V2));
        assert_ne!(a, b, "nonce aleatório: duas cifragens do mesmo valor não podem coincidir");
        assert!(!a.contains("audit-user-7391"));
        assert_eq!(decrypt_field(&key, "accounts", "username", 7, &a), Ok("audit-user-7391".to_string()));
        assert_eq!(decrypt_field(&key, "accounts", "username", 7, &b), Ok("audit-user-7391".to_string()));
    }

    #[test]
    fn field_ciphertext_copied_to_another_row_column_or_table_fails_authentication() {
        let key = [4u8; KEY_LEN];
        let stored = encrypt_field(&key, "accounts", "username", 7, "valor-ficticio").unwrap();
        assert_eq!(decrypt_field(&key, "accounts", "username", 8, &stored), Err(FieldError::Corrupt), "outra linha");
        assert_eq!(decrypt_field(&key, "accounts", "email", 7, &stored), Err(FieldError::Corrupt), "outra coluna");
        assert_eq!(decrypt_field(&key, "account_history", "username", 7, &stored), Err(FieldError::Corrupt), "outra tabela");
        assert_eq!(decrypt_field(&[5u8; KEY_LEN], "accounts", "username", 7, &stored), Err(FieldError::Corrupt), "outra chave");
    }

    #[test]
    fn field_aad_encoding_is_unambiguous() {
        assert_ne!(field_aad("a", "bc", 1), field_aad("ab", "c", 1));
        assert_ne!(field_aad("accounts", "name", 1), field_aad("accounts", "name", 256));
        assert_ne!(field_aad("accounts", "name", 1), field_aad("accounts", "name", -1));
    }

    #[test]
    fn field_tampering_unknown_version_and_legacy_plaintext() {
        let key = [4u8; KEY_LEN];
        let stored = encrypt_field(&key, "accounts", "name", 1, "x").unwrap();
        let mut chars: Vec<char> = stored.chars().collect();
        let last = chars.len() - 6;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, &tampered), Err(FieldError::Corrupt));
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, "enc:v2:%%%nao-base64"), Err(FieldError::Corrupt));
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, "enc:v3:AAAA"), Err(FieldError::UnknownVersion));
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, "enc:v99:"), Err(FieldError::UnknownVersion));
        // Sem prefixo de versão = legado em texto puro (inclusive texto parecido, mas não igual).
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, "texto legado"), Ok("texto legado".to_string()));
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, "enc:vX:abc"), Ok("enc:vX:abc".to_string()));
        assert_eq!(decrypt_field(&key, "accounts", "name", 1, ""), Ok(String::new()));
    }
}
