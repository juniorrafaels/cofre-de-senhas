//! Credenciais que protegem a DEK: senha mestra (padrão) ou duas senhas (opcional).
//!
//! # Protocolo
//!
//! A DEK nunca muda por causa de credenciais; o que muda é o "envelope" gravado em `vault_meta`.
//!
//! * **`single`** (`unlock_policy` NULL ou `'single'` — cofres legados): `KEK = Argon2id(senha,
//!   kdf_salt, kdf_params)` e `wrapped_dek = XChaCha20-Poly1305(KEK, DEK)`. Formato idêntico ao
//!   de sempre.
//! * **`dual-v1`**: `K1 = Argon2id(senha1, kdf_salt, kdf_params)`, `K2 = Argon2id(senha2,
//!   unlock2_salt, unlock2_kdf_params)` (salts exclusivos, parâmetros versionados e validados),
//!   `KEK = HKDF-SHA256(salt = "cofre/unlock/dual-v1/hkdf-salt", ikm = len(K1)||K1||len(K2)||K2,
//!   info = "cofre/unlock/dual-v1/kek")` e `wrapped_dek = XChaCha20-Poly1305(KEK, DEK, AAD =
//!   contexto||len(salt1)||salt1||len(salt2)||salt2)`. O campo `wrapped_dek` é SUBSTITUÍDO, então
//!   não resta nenhum envelope que aceite só a senha 1; a ordem importa (K1 ≠ K2) e a codificação
//!   com prefixo de tamanho evita ambiguidade. Custo de adivinhar = custo da senha 1 × custo da
//!   senha 2: nenhuma das duas pode ser confirmada isoladamente.
//!
//! Recuperação (Recovery Key, perguntas/Shamir, segunda senha de recuperação) guarda a MESMA DEK em
//! envelopes independentes e, por desenho, NÃO depende desta política: ver `SECURITY.md`.
//!
//! Toda troca de política é UMA única instrução `UPDATE` dentro de uma transação, relida e
//! verificada (o envelope gravado precisa devolver exatamente a DEK) antes do `COMMIT`.

use crate::crypto::{self, KdfParams, KEY_LEN};
use crate::lockout::{self, Clock, ThrottleError};
use hkdf::Hkdf;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const POLICY_SINGLE: &str = "single";
pub const POLICY_DUAL_V1: &str = "dual-v1";

const DUAL_AAD_CONTEXT: &[u8] = b"cofre/unlock/dual-v1/wrapped-dek";
const DUAL_HKDF_SALT: &[u8] = b"cofre/unlock/dual-v1/hkdf-salt";
const DUAL_HKDF_INFO: &[u8] = b"cofre/unlock/dual-v1/kek";

/// Tamanho máximo aceito para qualquer senha recebida (limita Argon2/memória com entrada absurda).
pub const MAX_PASSWORD_CHARS: usize = 1024;
pub const MIN_PASSWORD_CHARS: usize = 8;
const MIN_SALT_LEN: usize = 8;
const MAX_SALT_LEN: usize = 64;

pub const MSG_WRONG: &str = "Senha incorreta.";
pub const MSG_NOT_CREATED: &str = "O cofre ainda não foi criado.";
pub const MSG_GENERIC: &str = "Não foi possível concluir a operação.";
pub const MSG_CORRUPT: &str =
    "Os dados de proteção do cofre estão corrompidos ou usam um formato não suportado.";
pub const ERR_SECOND_PASSWORD_REQUIRED: &str = "E_SECOND_PASSWORD_REQUIRED";
pub const MSG_DUAL_ALREADY_ON: &str = "O desbloqueio com duas senhas já está ativado.";
pub const MSG_DUAL_NOT_ON: &str = "O desbloqueio com duas senhas não está ativado.";
pub const MSG_SECOND_SAME_AS_FIRST: &str = "A segunda senha precisa ser diferente da primeira.";
pub const MSG_SECOND_TOO_SHORT: &str = "A segunda senha deve ter pelo menos 8 caracteres.";
pub const MSG_PASSWORD_TOO_LONG: &str = "A senha é longa demais.";

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    NotInitialized,
    SecondPasswordRequired,
    /// A única falha que é "senha incorreta": o AEAD do envelope não autenticou.
    Wrong,
    /// Metadados ilegíveis/fora dos limites/versão desconhecida. NÃO é senha incorreta.
    Corrupt,
    Locked {
        remaining_ms: i64,
        failed_count: i64,
    },
    Internal(String),
}

/// Código de erro estruturado para o frontend: `E_LOCKED:<segundos>:<falhas>`.
pub fn locked_ipc(remaining_ms: i64, failed_count: i64) -> String {
    let secs = (remaining_ms + 999) / 1000;
    format!("E_LOCKED:{secs}:{failed_count}")
}

impl AuthError {
    /// Mensagem para a WebView. Nunca contém senha, chave ou valor secreto.
    pub fn to_ipc(&self) -> String {
        match self {
            AuthError::NotInitialized => MSG_NOT_CREATED.to_string(),
            AuthError::SecondPasswordRequired => ERR_SECOND_PASSWORD_REQUIRED.to_string(),
            AuthError::Wrong => MSG_WRONG.to_string(),
            AuthError::Corrupt => MSG_CORRUPT.to_string(),
            AuthError::Locked {
                remaining_ms,
                failed_count,
            } => locked_ipc(*remaining_ms, *failed_count),
            AuthError::Internal(_) => MSG_GENERIC.to_string(),
        }
    }
}

fn map_throttle(e: ThrottleError) -> AuthError {
    match e {
        ThrottleError::Locked {
            remaining_ms,
            failed_count,
        } => AuthError::Locked {
            remaining_ms,
            failed_count,
        },
        ThrottleError::Internal(e) => AuthError::Internal(e),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockPolicy {
    Single,
    Dual,
}

struct UnlockMeta {
    salt: Vec<u8>,
    params_json: String,
    wrapped: Vec<u8>,
    policy: Option<String>,
    salt2: Option<Vec<u8>>,
    params2_json: Option<String>,
}

fn read_unlock_meta(conn: &Connection) -> Result<UnlockMeta, AuthError> {
    conn.query_row(
        "SELECT kdf_salt, kdf_params, wrapped_dek, unlock_policy, unlock2_salt, unlock2_kdf_params FROM vault_meta WHERE id = 1",
        [],
        |row| {
            Ok(UnlockMeta {
                salt: row.get(0)?,
                params_json: row.get(1)?,
                wrapped: row.get(2)?,
                policy: row.get(3)?,
                salt2: row.get(4)?,
                params2_json: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(|e| match e {
        rusqlite::Error::InvalidColumnType(..) | rusqlite::Error::FromSqlConversionFailure(..) => AuthError::Corrupt,
        other => AuthError::Internal(other.to_string()),
    })?
    .ok_or(AuthError::NotInitialized)
}

fn policy_of(meta: &UnlockMeta) -> Result<UnlockPolicy, AuthError> {
    match meta.policy.as_deref() {
        None | Some(POLICY_SINGLE) => Ok(UnlockPolicy::Single),
        Some(POLICY_DUAL_V1) => Ok(UnlockPolicy::Dual),
        Some(_) => Err(AuthError::Corrupt), // versão de política desconhecida (cofre de versão mais nova)
    }
}

pub fn read_policy(conn: &Connection) -> Result<UnlockPolicy, AuthError> {
    policy_of(&read_unlock_meta(conn)?)
}

fn parse_params(json: &str) -> Result<KdfParams, AuthError> {
    let params: KdfParams = serde_json::from_str(json).map_err(|_| AuthError::Corrupt)?;
    if !params.is_within_bounds() {
        return Err(AuthError::Corrupt);
    }
    Ok(params)
}

fn check_salt(salt: &[u8]) -> Result<(), AuthError> {
    if (MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        Ok(())
    } else {
        Err(AuthError::Corrupt)
    }
}

fn derive(
    password: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, AuthError> {
    crypto::derive_key(password, salt, params).map_err(|e| match e {
        crypto::CryptoError::InvalidKdfParams => AuthError::Corrupt,
        _ => AuthError::Internal("falha na derivação de chave".to_string()),
    })
}

fn push_len_prefixed(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u32).to_be_bytes());
    out.extend_from_slice(part);
}

fn derive_dual_kek(k1: &[u8; KEY_LEN], k2: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * (KEY_LEN + 4)));
    push_len_prefixed(&mut ikm, k1);
    push_len_prefixed(&mut ikm, k2);
    let hk = Hkdf::<Sha256>::new(Some(DUAL_HKDF_SALT), &ikm);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(DUAL_HKDF_INFO, kek.as_mut())
        .expect("comprimento de saída HKDF válido");
    kek
}

fn dual_aad(salt1: &[u8], salt2: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DUAL_AAD_CONTEXT.len() + salt1.len() + salt2.len() + 12);
    push_len_prefixed(&mut aad, DUAL_AAD_CONTEXT);
    push_len_prefixed(&mut aad, salt1);
    push_len_prefixed(&mut aad, salt2);
    aad
}

fn into_dek(plain: &[u8]) -> Result<[u8; 32], AuthError> {
    if plain.len() != 32 {
        return Err(AuthError::Corrupt); // o AEAD autenticou, mas o conteúdo não é uma DEK
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(plain);
    Ok(dek)
}

/// Desembrulha a DEK com as credenciais dadas, SEM bloqueio progressivo (use `authenticate` para
/// verificar credenciais de um usuário). Falha de autenticação do envelope = `Wrong`; metadados
/// estruturalmente inválidos = `Corrupt`.
pub fn unwrap_dek(
    conn: &Connection,
    password: &str,
    password2: Option<&str>,
) -> Result<[u8; 32], AuthError> {
    let meta = read_unlock_meta(conn)?;
    check_salt(&meta.salt)?;
    let params1 = parse_params(&meta.params_json)?;
    match policy_of(&meta)? {
        UnlockPolicy::Single => {
            let kek = derive(password, &meta.salt, &params1)?;
            let plain = crypto::decrypt(&kek, &meta.wrapped).map_err(|_| AuthError::Wrong)?;
            into_dek(&plain)
        }
        UnlockPolicy::Dual => {
            let password2 = password2
                .filter(|p| !p.is_empty())
                .ok_or(AuthError::SecondPasswordRequired)?;
            let salt2 = meta.salt2.as_deref().ok_or(AuthError::Corrupt)?;
            check_salt(salt2)?;
            let params2 = parse_params(meta.params2_json.as_deref().ok_or(AuthError::Corrupt)?)?;
            let k1 = derive(password, &meta.salt, &params1)?;
            let k2 = derive(password2, salt2, &params2)?;
            let kek = derive_dual_kek(&k1, &k2);
            let plain = crypto::decrypt_aad(&kek, &meta.wrapped, &dual_aad(&meta.salt, salt2))
                .map_err(|_| AuthError::Wrong)?;
            into_dek(&plain)
        }
    }
}

/// Verifica credenciais aplicando o bloqueio progressivo (se ativado). Ordem: política (segunda
/// senha ausente não gasta tentativa) → cobrança da tentativa → verificação → limpar/manter/devolver.
pub fn authenticate(
    conn: &Connection,
    password: &str,
    password2: Option<&str>,
    clock: &dyn Clock,
) -> Result<[u8; 32], AuthError> {
    let policy = read_policy(conn)?;
    let password2 = password2.filter(|p| !p.is_empty());
    if policy == UnlockPolicy::Dual && password2.is_none() {
        return Err(AuthError::SecondPasswordRequired);
    }
    let ticket = lockout::begin(conn, lockout::SCOPE_UNLOCK, clock).map_err(map_throttle)?;
    match unwrap_dek(conn, password, password2) {
        Ok(dek) => {
            ticket.succeed(conn);
            Ok(dek)
        }
        Err(AuthError::Wrong) => Err(AuthError::Wrong), // a cobrança fica: foi uma senha errada de verdade
        Err(other) => {
            ticket.refund(conn); // erro interno/corrupção não conta como tentativa de senha
            Err(other)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Envelopes (gravar)
// ---------------------------------------------------------------------------------------------

pub struct SingleWrap {
    salt: Vec<u8>,
    params_json: String,
    wrapped: Vec<u8>,
}

pub struct DualWrap {
    salt1: Vec<u8>,
    params1_json: String,
    salt2: Vec<u8>,
    params2_json: String,
    wrapped: Vec<u8>,
}

pub fn wrap_single(
    password: &str,
    dek: &[u8; 32],
    params: &KdfParams,
) -> Result<SingleWrap, String> {
    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let kek = crypto::derive_key(password, &salt, params).map_err(|_| MSG_GENERIC.to_string())?;
    let wrapped = crypto::encrypt(&kek, dek).map_err(|_| MSG_GENERIC.to_string())?;
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    Ok(SingleWrap {
        salt,
        params_json,
        wrapped,
    })
}

pub fn wrap_dual(
    password1: &str,
    password2: &str,
    dek: &[u8; 32],
    params1: &KdfParams,
    params2: &KdfParams,
) -> Result<DualWrap, String> {
    let salt1 = crypto::random_bytes(crypto::SALT_LEN);
    let salt2 = crypto::random_bytes(crypto::SALT_LEN);
    let k1 = crypto::derive_key(password1, &salt1, params1).map_err(|_| MSG_GENERIC.to_string())?;
    let k2 = crypto::derive_key(password2, &salt2, params2).map_err(|_| MSG_GENERIC.to_string())?;
    let kek = derive_dual_kek(&k1, &k2);
    let wrapped = crypto::encrypt_aad(&kek, dek, &dual_aad(&salt1, &salt2))
        .map_err(|_| MSG_GENERIC.to_string())?;
    Ok(DualWrap {
        salt1,
        params1_json: serde_json::to_string(params1).map_err(|e| e.to_string())?,
        salt2,
        params2_json: serde_json::to_string(params2).map_err(|e| e.to_string())?,
        wrapped,
    })
}

fn expect_one_row(changed: usize) -> Result<(), String> {
    if changed == 1 {
        Ok(())
    } else {
        Err(MSG_NOT_CREATED.to_string())
    }
}

pub fn store_single(conn: &Connection, wrap: &SingleWrap) -> Result<(), String> {
    let changed = conn
        .execute(
            "UPDATE vault_meta SET kdf_salt = ?1, kdf_params = ?2, wrapped_dek = ?3, unlock_policy = ?4, \
             unlock2_salt = NULL, unlock2_kdf_params = NULL WHERE id = 1",
            params![wrap.salt, wrap.params_json, wrap.wrapped, POLICY_SINGLE],
        )
        .map_err(|e| e.to_string())?;
    expect_one_row(changed)
}

pub fn store_dual(conn: &Connection, wrap: &DualWrap) -> Result<(), String> {
    let changed = conn
        .execute(
            "UPDATE vault_meta SET kdf_salt = ?1, kdf_params = ?2, wrapped_dek = ?3, unlock_policy = ?4, \
             unlock2_salt = ?5, unlock2_kdf_params = ?6 WHERE id = 1",
            params![wrap.salt1, wrap.params1_json, wrap.wrapped, POLICY_DUAL_V1, wrap.salt2, wrap.params2_json],
        )
        .map_err(|e| e.to_string())?;
    expect_one_row(changed)
}

/// Executa `f` numa transação `BEGIN IMMEDIATE`: `COMMIT` se `Ok`, `ROLLBACK` se `Err`.
pub fn in_immediate_tx<T>(
    conn: &Connection,
    f: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| e.to_string())?;
    match f() {
        Ok(value) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(value),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e.to_string())
            }
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Grava o envelope e confirma, relendo do banco, que as credenciais novas devolvem exatamente a
/// mesma DEK. Qualquer falha desfaz TUDO (estado anterior íntegro).
fn store_verified(
    conn: &Connection,
    dek: &[u8; 32],
    store: impl FnOnce(&Connection) -> Result<(), String>,
    password: &str,
    password2: Option<&str>,
) -> Result<(), String> {
    in_immediate_tx(conn, || {
        store(conn)?;
        match unwrap_dek(conn, password, password2) {
            Ok(check) if &check == dek => Ok(()),
            _ => Err(MSG_GENERIC.to_string()),
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Operações de política (todas reautenticam as credenciais ATUAIS dentro da própria chamada)
// ---------------------------------------------------------------------------------------------

pub fn validate_new_password(password: &str, too_short_msg: &str) -> Result<(), String> {
    let chars = password.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err(too_short_msg.to_string());
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(MSG_PASSWORD_TOO_LONG.to_string());
    }
    Ok(())
}

/// Ativa o desbloqueio com duas senhas: a senha mestra atual vira a senha 1 e `new_second` a senha 2.
pub fn enable_dual(
    conn: &Connection,
    current: &str,
    new_second: &str,
    params1: &KdfParams,
    params2: &KdfParams,
    clock: &dyn Clock,
) -> Result<(), String> {
    validate_new_password(new_second, MSG_SECOND_TOO_SHORT)?;
    if new_second == current {
        return Err(MSG_SECOND_SAME_AS_FIRST.to_string());
    }
    if read_policy(conn).map_err(|e| e.to_ipc())? == UnlockPolicy::Dual {
        return Err(MSG_DUAL_ALREADY_ON.to_string());
    }
    let dek = authenticate(conn, current, None, clock).map_err(|e| e.to_ipc())?;
    let wrap = wrap_dual(current, new_second, &dek, params1, params2)?;
    store_verified(
        conn,
        &dek,
        |c| store_dual(c, &wrap),
        current,
        Some(new_second),
    )
}

/// Desativa: volta ao envelope de uma senha (a senha 1 continua sendo a senha mestra).
pub fn disable_dual(
    conn: &Connection,
    current1: &str,
    current2: &str,
    params: &KdfParams,
    clock: &dyn Clock,
) -> Result<(), String> {
    if read_policy(conn).map_err(|e| e.to_ipc())? != UnlockPolicy::Dual {
        return Err(MSG_DUAL_NOT_ON.to_string());
    }
    let dek = authenticate(conn, current1, Some(current2), clock).map_err(|e| e.to_ipc())?;
    let wrap = wrap_single(current1, &dek, params)?;
    store_verified(conn, &dek, |c| store_single(c, &wrap), current1, None)
}

/// Troca a segunda senha (a primeira permanece). Reautentica as duas atuais.
pub fn change_second(
    conn: &Connection,
    current1: &str,
    current2: &str,
    new_second: &str,
    params1: &KdfParams,
    params2: &KdfParams,
    clock: &dyn Clock,
) -> Result<(), String> {
    validate_new_password(new_second, MSG_SECOND_TOO_SHORT)?;
    if new_second == current1 {
        return Err(MSG_SECOND_SAME_AS_FIRST.to_string());
    }
    if read_policy(conn).map_err(|e| e.to_ipc())? != UnlockPolicy::Dual {
        return Err(MSG_DUAL_NOT_ON.to_string());
    }
    let dek = authenticate(conn, current1, Some(current2), clock).map_err(|e| e.to_ipc())?;
    let wrap = wrap_dual(current1, new_second, &dek, params1, params2)?;
    store_verified(
        conn,
        &dek,
        |c| store_dual(c, &wrap),
        current1,
        Some(new_second),
    )
}

/// Troca a senha mestra (senha 1), mantendo a política atual (e a senha 2, se houver).
pub fn change_first(
    conn: &Connection,
    current1: &str,
    current2: Option<&str>,
    new_first: &str,
    params: &KdfParams,
    clock: &dyn Clock,
) -> Result<[u8; 32], String> {
    let policy = read_policy(conn).map_err(|e| e.to_ipc())?;
    let dek = authenticate(conn, current1, current2, clock).map_err(|e| e.to_ipc())?;
    match policy {
        UnlockPolicy::Single => {
            let wrap = wrap_single(new_first, &dek, params)?;
            store_verified(conn, &dek, |c| store_single(c, &wrap), new_first, None)?;
        }
        UnlockPolicy::Dual => {
            let second = current2
                .filter(|p| !p.is_empty())
                .ok_or_else(|| ERR_SECOND_PASSWORD_REQUIRED.to_string())?;
            if new_first == second {
                return Err(MSG_SECOND_SAME_AS_FIRST.to_string());
            }
            let wrap = wrap_dual(new_first, second, &dek, params, params)?;
            store_verified(
                conn,
                &dek,
                |c| store_dual(c, &wrap),
                new_first,
                Some(second),
            )?;
        }
    }
    Ok(dek)
}

/// Redefinição após recuperação (a DEK já foi obtida por um método de recuperação): grava uma
/// ÚNICA senha nova e volta a política para `single` — o método de recuperação já provou o acesso
/// à DEK, e manter a política antiga sem as senhas antigas deixaria o cofre inabrível.
pub fn reset_to_single(
    conn: &Connection,
    dek: &[u8; 32],
    new_password: &str,
    params: &KdfParams,
) -> Result<(), String> {
    let wrap = wrap_single(new_password, dek, params)?;
    store_verified(conn, dek, |c| store_single(c, &wrap), new_password, None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lockout::{Clock, SystemClock};

    pub fn fast_params() -> KdfParams {
        KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    /// Cofre sintético no formato LEGADO (como o `create_vault` antigo: sem colunas novas preenchidas).
    pub fn legacy_vault(password: &str, dek: [u8; 32]) -> Connection {
        legacy_vault_in(Connection::open_in_memory().unwrap(), password, dek)
    }

    /// Mesmo cofre legado, mas sobre a conexão dada (ex.: um arquivo em disco).
    pub fn legacy_vault_in(conn: Connection, password: &str, dek: [u8; 32]) -> Connection {
        crate::db::init_schema(&conn).unwrap();
        let params = fast_params();
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let kek = crypto::derive_key(password, &salt, &params).unwrap();
        let wrapped = crypto::encrypt(&kek, &dek).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![salt, serde_json::to_string(&params).unwrap(), wrapped, crypto::encrypt(&dek, b"vault-dek-check-v1").unwrap(), "now"],
        )
        .unwrap();
        conn
    }

    pub struct TestClock(pub std::cell::Cell<i64>);
    impl Clock for TestClock {
        fn now_ms(&self) -> i64 {
            self.0.get()
        }
    }

    const DEK: [u8; 32] = [9u8; 32];

    fn enable(conn: &Connection, first: &str, second: &str) {
        enable_dual(
            conn,
            first,
            second,
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
    }

    #[test]
    fn legacy_vault_with_null_policy_unlocks_with_one_password() {
        let conn = legacy_vault("senha-legada-1", DEK);
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Single));
        assert_eq!(unwrap_dek(&conn, "senha-legada-1", None), Ok(DEK));
        assert_eq!(
            unwrap_dek(&conn, "outra-senha", None),
            Err(AuthError::Wrong)
        );
        // Uma segunda senha enviada sem necessidade é simplesmente ignorada no modo padrão.
        assert_eq!(unwrap_dek(&conn, "senha-legada-1", Some("lixo")), Ok(DEK));
    }

    #[test]
    fn dual_requires_both_passwords_and_rejects_every_partial_or_swapped_combination() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Dual));

        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-dois-bbbb")),
            Ok(DEK)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", None),
            Err(AuthError::SecondPasswordRequired)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("")),
            Err(AuthError::SecondPasswordRequired)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("errada-12345")),
            Err(AuthError::Wrong)
        );
        assert_eq!(
            unwrap_dek(&conn, "errada-12345", Some("senha-dois-bbbb")),
            Err(AuthError::Wrong)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-dois-bbbb", Some("senha-um-aaaa")),
            Err(AuthError::Wrong),
            "ordem importa"
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-um-aaaa")),
            Err(AuthError::Wrong)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-dois-bbbb", Some("senha-dois-bbbb")),
            Err(AuthError::Wrong)
        );
    }

    #[test]
    fn no_alternative_path_accepts_the_first_password_alone_after_enabling_dual() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");

        // Caminho legado "à mão": KEK só da senha 1 com o salt/params gravados NÃO abre o envelope.
        let (salt, params_json, wrapped): (Vec<u8>, String, Vec<u8>) = conn
            .query_row(
                "SELECT kdf_salt, kdf_params, wrapped_dek FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let params: KdfParams = serde_json::from_str(&params_json).unwrap();
        let kek1 = crypto::derive_key("senha-um-aaaa", &salt, &params).unwrap();
        assert!(crypto::decrypt(&kek1, &wrapped).is_err());
        assert!(crypto::decrypt_aad(&kek1, &wrapped, &dual_aad(&salt, &[0u8; 16])).is_err());
        // E a senha 2 sozinha, em qualquer posição, também não.
        let salt2: Vec<u8> = conn
            .query_row("SELECT unlock2_salt FROM vault_meta", [], |r| r.get(0))
            .unwrap();
        let kek2 = crypto::derive_key("senha-dois-bbbb", &salt2, &params).unwrap();
        assert!(crypto::decrypt(&kek2, &wrapped).is_err());
    }

    #[test]
    fn enabling_keeps_the_dek_and_data_intact_and_disabling_restores_single_password() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        let secret = crypto::encrypt_to_base64(&DEK, "SEGREDO_FICTICIO_123").unwrap();
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        let dek = unwrap_dek(&conn, "senha-um-aaaa", Some("senha-dois-bbbb")).unwrap();
        assert_eq!(dek, DEK);
        assert_eq!(
            crypto::decrypt_from_base64(&dek, &secret).unwrap(),
            "SEGREDO_FICTICIO_123"
        );

        disable_dual(
            &conn,
            "senha-um-aaaa",
            "senha-dois-bbbb",
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Single));
        assert_eq!(unwrap_dek(&conn, "senha-um-aaaa", None), Ok(DEK));
        let leftover: (Option<Vec<u8>>, Option<String>) = conn
            .query_row(
                "SELECT unlock2_salt, unlock2_kdf_params FROM vault_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(leftover, (None, None), "nada da segunda senha sobra");
    }

    #[test]
    fn enabling_and_changing_require_current_credentials() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        let before = vault_meta_snapshot(&conn);
        assert!(enable_dual(
            &conn,
            "senha-errada-1",
            "senha-dois-bbbb",
            &fast_params(),
            &fast_params(),
            &SystemClock
        )
        .is_err());
        assert_eq!(
            vault_meta_snapshot(&conn),
            before,
            "senha atual errada não altera nada"
        );

        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        let dual_before = vault_meta_snapshot(&conn);
        assert!(change_second(
            &conn,
            "senha-um-aaaa",
            "errada-12345",
            "terceira-senha-1",
            &fast_params(),
            &fast_params(),
            &SystemClock
        )
        .is_err());
        assert!(disable_dual(
            &conn,
            "senha-um-aaaa",
            "errada-12345",
            &fast_params(),
            &SystemClock
        )
        .is_err());
        assert_eq!(vault_meta_snapshot(&conn), dual_before);
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-dois-bbbb")),
            Ok(DEK)
        );
    }

    #[test]
    fn second_password_validation_rules() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        let e = |second: &str| {
            enable_dual(
                &conn,
                "senha-um-aaaa",
                second,
                &fast_params(),
                &fast_params(),
                &SystemClock,
            )
            .unwrap_err()
        };
        assert_eq!(e("curta"), MSG_SECOND_TOO_SHORT);
        assert_eq!(e("senha-um-aaaa"), MSG_SECOND_SAME_AS_FIRST);
        assert_eq!(
            e(&"x".repeat(MAX_PASSWORD_CHARS + 1)),
            MSG_PASSWORD_TOO_LONG
        );
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Single));
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        assert_eq!(
            enable_dual(
                &conn,
                "senha-um-aaaa",
                "terceira-senha-1",
                &fast_params(),
                &fast_params(),
                &SystemClock
            )
            .unwrap_err(),
            MSG_DUAL_ALREADY_ON
        );
    }

    #[test]
    fn changing_the_second_password_invalidates_the_old_one_and_keeps_the_dek() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        change_second(
            &conn,
            "senha-um-aaaa",
            "senha-dois-bbbb",
            "senha-tres-cccc",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-dois-bbbb")),
            Err(AuthError::Wrong)
        );
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-tres-cccc")),
            Ok(DEK)
        );
    }

    #[test]
    fn changing_the_first_password_keeps_dek_in_both_modes() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        change_first(
            &conn,
            "senha-um-aaaa",
            None,
            "senha-nova-1111",
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(unwrap_dek(&conn, "senha-nova-1111", None), Ok(DEK));
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", None),
            Err(AuthError::Wrong)
        );

        enable(&conn, "senha-nova-1111", "senha-dois-bbbb");
        change_first(
            &conn,
            "senha-nova-1111",
            Some("senha-dois-bbbb"),
            "senha-nova-2222",
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-nova-2222", Some("senha-dois-bbbb")),
            Ok(DEK)
        );
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Dual));
        // Sem a segunda senha atual, não troca.
        assert_eq!(
            change_first(
                &conn,
                "senha-nova-2222",
                None,
                "senha-nova-3333",
                &fast_params(),
                &SystemClock
            )
            .unwrap_err(),
            ERR_SECOND_PASSWORD_REQUIRED
        );
    }

    #[test]
    fn reset_after_recovery_returns_to_single_password_and_keeps_dek() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        reset_to_single(&conn, &DEK, "senha-redefinida-1", &fast_params()).unwrap();
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Single));
        assert_eq!(unwrap_dek(&conn, "senha-redefinida-1", None), Ok(DEK));
    }

    fn vault_meta_snapshot(conn: &Connection) -> Vec<String> {
        conn.query_row(
            "SELECT hex(kdf_salt), kdf_params, hex(wrapped_dek), coalesce(unlock_policy,''), coalesce(hex(unlock2_salt),''), coalesce(unlock2_kdf_params,'') FROM vault_meta",
            [],
            |r| (0..6).map(|i| r.get::<_, String>(i)).collect(),
        )
        .unwrap()
    }

    #[test]
    fn failure_while_storing_leaves_the_previous_state_intact() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        let before = vault_meta_snapshot(&conn);
        // Faz o UPDATE falhar (simula disco cheio/erro no meio da troca).
        conn.execute_batch("CREATE TRIGGER boom BEFORE UPDATE ON vault_meta BEGIN SELECT RAISE(ABORT, 'falha simulada'); END;").unwrap();
        assert!(enable_dual(
            &conn,
            "senha-um-aaaa",
            "senha-dois-bbbb",
            &fast_params(),
            &fast_params(),
            &SystemClock
        )
        .is_err());
        assert_eq!(vault_meta_snapshot(&conn), before);
        conn.execute_batch("DROP TRIGGER boom").unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", None),
            Ok(DEK),
            "o cofre continua abrindo com a senha antiga"
        );
        assert_eq!(read_policy(&conn), Ok(UnlockPolicy::Single));
    }

    #[test]
    fn corrupted_or_unknown_metadata_is_reported_as_corrupt_not_as_wrong_password() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        conn.execute("UPDATE vault_meta SET kdf_params = '{\"memory_kib\":4294967295,\"iterations\":1,\"parallelism\":1}'", []).unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", None),
            Err(AuthError::Corrupt)
        );
        conn.execute("UPDATE vault_meta SET kdf_params = 'nao-e-json'", [])
            .unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", None),
            Err(AuthError::Corrupt)
        );

        let conn = legacy_vault("senha-um-aaaa", DEK);
        conn.execute("UPDATE vault_meta SET unlock_policy = 'dual-v9'", [])
            .unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("x")),
            Err(AuthError::Corrupt),
            "versão desconhecida"
        );

        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        conn.execute("UPDATE vault_meta SET unlock2_salt = NULL", [])
            .unwrap();
        assert_eq!(
            unwrap_dek(&conn, "senha-um-aaaa", Some("senha-dois-bbbb")),
            Err(AuthError::Corrupt)
        );
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_schema(&conn).unwrap();
        assert_eq!(unwrap_dek(&conn, "x", None), Err(AuthError::NotInitialized));
    }

    // ---- integração com o bloqueio progressivo ----

    #[test]
    fn authenticate_charges_wrong_passwords_and_clears_on_success() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        lockout::set_enabled(&conn, true).unwrap();
        let clock = TestClock(std::cell::Cell::new(1_000_000));

        assert_eq!(
            authenticate(&conn, "errada-1234", None, &clock),
            Err(AuthError::Wrong)
        );
        // Durante a espera, até a senha CERTA é recusada (sem verificar nada).
        match authenticate(&conn, "senha-um-aaaa", None, &clock) {
            Err(AuthError::Locked {
                remaining_ms,
                failed_count,
            }) => assert_eq!((remaining_ms, failed_count), (15_000, 1)),
            other => panic!("esperava bloqueio, veio {other:?}"),
        }
        clock.0.set(1_000_000 + 15_000);
        assert_eq!(authenticate(&conn, "senha-um-aaaa", None, &clock), Ok(DEK));
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_UNLOCK, &clock)
                .unwrap()
                .failed_count,
            0
        );
    }

    #[test]
    fn missing_second_password_and_internal_errors_do_not_count_as_wrong_password_attempts() {
        let conn = legacy_vault("senha-um-aaaa", DEK);
        enable(&conn, "senha-um-aaaa", "senha-dois-bbbb");
        lockout::set_enabled(&conn, true).unwrap();
        let clock = TestClock(std::cell::Cell::new(0));

        for _ in 0..5 {
            assert_eq!(
                authenticate(&conn, "senha-um-aaaa", None, &clock),
                Err(AuthError::SecondPasswordRequired)
            );
        }
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_UNLOCK, &clock)
                .unwrap()
                .failed_count,
            0
        );

        // Metadados corrompidos: erro estrutural, devolvido sem contar como senha errada.
        conn.execute("UPDATE vault_meta SET unlock2_kdf_params = 'lixo'", [])
            .unwrap();
        assert_eq!(
            authenticate(&conn, "senha-um-aaaa", Some("senha-dois-bbbb"), &clock),
            Err(AuthError::Corrupt)
        );
        assert_eq!(
            lockout::status(&conn, lockout::SCOPE_UNLOCK, &clock)
                .unwrap()
                .failed_count,
            0
        );
    }

    #[test]
    fn locked_error_is_exposed_with_a_structured_code_for_the_interface() {
        assert_eq!(locked_ipc(15_000, 1), "E_LOCKED:15:1");
        assert_eq!(
            locked_ipc(14_001, 3),
            "E_LOCKED:15:3",
            "arredonda para cima"
        );
        assert_eq!(
            AuthError::SecondPasswordRequired.to_ipc(),
            "E_SECOND_PASSWORD_REQUIRED"
        );
        assert_eq!(AuthError::Wrong.to_ipc(), "Senha incorreta.");
        assert_ne!(AuthError::Corrupt.to_ipc(), AuthError::Wrong.to_ipc());
        assert_eq!(
            AuthError::Internal("detalhe secreto".into()).to_ipc(),
            MSG_GENERIC,
            "detalhes internos não vazam"
        );
    }

    #[test]
    fn kek_derivation_is_domain_separated_and_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(*derive_dual_kek(&a, &b), *derive_dual_kek(&b, &a));
        assert_ne!(*derive_dual_kek(&a, &b), *derive_dual_kek(&a, &a));
        assert_ne!(
            dual_aad(b"ab", b"c"),
            dual_aad(b"a", b"bc"),
            "codificação com prefixo de tamanho é inequívoca"
        );
    }

    // ---- nenhum segredo em disco nem em logs ----

    fn all_bytes_under(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                out.push((
                    path.file_name().unwrap().to_string_lossy().to_string(),
                    std::fs::read(&path).unwrap(),
                ));
            }
        }
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn no_password_dek_or_derived_key_ever_reaches_the_database_files() {
        let dir = std::env::temp_dir().join(format!("cofre-secret-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dek = [0xA7u8; 32];
        let conn = legacy_vault_in(
            Connection::open(dir.join("vault.db")).unwrap(),
            "SENHA-UM-PARA-VARREDURA",
            dek,
        );
        enable_dual(
            &conn,
            "SENHA-UM-PARA-VARREDURA",
            "SENHA-DOIS-PARA-VARREDURA",
            &fast_params(),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        crate::commands::recovery_password::set_recovery_password_core(
            &conn,
            &zeroize::Zeroizing::new("SENHA-UM-PARA-VARREDURA".to_string()),
            Some(&zeroize::Zeroizing::new(
                "SENHA-DOIS-PARA-VARREDURA".to_string(),
            )),
            &zeroize::Zeroizing::new("SENHA-REC-PARA-VARREDURA".to_string()),
            &fast_params(),
            &SystemClock,
        )
        .unwrap();
        crate::lockout::set_enabled(&conn, true).unwrap();
        let _ = authenticate(
            &conn,
            "ERRADA-PARA-VARREDURA",
            Some("OUTRA-ERRADA-VARREDURA"),
            &SystemClock,
        );
        let _ = authenticate(
            &conn,
            "SENHA-UM-PARA-VARREDURA",
            Some("SENHA-DOIS-PARA-VARREDURA"),
            &SystemClock,
        );
        drop(conn); // fecha (faz checkpoint do WAL)

        // Chaves derivadas que o fluxo calculou: nunca devem estar no disco.
        let params = fast_params();
        let (salt1, salt2): (Vec<u8>, Vec<u8>) = {
            let c = Connection::open(dir.join("vault.db")).unwrap();
            c.query_row("SELECT kdf_salt, unlock2_salt FROM vault_meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
        };
        let k1 = crypto::derive_key("SENHA-UM-PARA-VARREDURA", &salt1, &params).unwrap();
        let k2 = crypto::derive_key("SENHA-DOIS-PARA-VARREDURA", &salt2, &params).unwrap();
        let kek = derive_dual_kek(&k1, &k2);

        let secrets: Vec<(&str, Vec<u8>)> = vec![
            ("senha 1", b"SENHA-UM-PARA-VARREDURA".to_vec()),
            ("senha 2", b"SENHA-DOIS-PARA-VARREDURA".to_vec()),
            ("senha de recuperação", b"SENHA-REC-PARA-VARREDURA".to_vec()),
            ("tentativa errada", b"ERRADA-PARA-VARREDURA".to_vec()),
            ("DEK", dek.to_vec()),
            ("K1", k1.to_vec()),
            ("K2", k2.to_vec()),
            ("KEK dual", kek.to_vec()),
        ];
        let files = all_bytes_under(&dir);
        assert!(!files.is_empty());
        for (file, bytes) in &files {
            for (name, secret) in &secrets {
                assert!(
                    !contains(bytes, secret),
                    "{name} apareceu em claro no arquivo {file}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn production_code_of_the_credential_modules_never_uses_log_macros() {
        // Sem println!/eprintln!/dbg!/log em código de produção dos módulos que manipulam senhas e
        // chaves: não há como uma senha ou chave ir parar num log. (`state.rs` só registra o erro de
        // E/S do arquivo de controle, sem nenhum segredo.)
        for (name, src) in [
            ("auth.rs", include_str!("auth.rs")),
            ("lockout.rs", include_str!("lockout.rs")),
            ("account_status.rs", include_str!("account_status.rs")),
            (
                "commands/recovery_password.rs",
                include_str!("commands/recovery_password.rs"),
            ),
            (
                "commands/unlock_policy.rs",
                include_str!("commands/unlock_policy.rs"),
            ),
            ("commands/vault.rs", include_str!("commands/vault.rs")),
            (
                "commands/recovery_key.rs",
                include_str!("commands/recovery_key.rs"),
            ),
            (
                "commands/security_questions.rs",
                include_str!("commands/security_questions.rs"),
            ),
            ("instance_lock.rs", include_str!("instance_lock.rs")),
        ] {
            let production = src.split("#[cfg(test)]").next().unwrap();
            for mac in ["println!", "eprintln!", "dbg!", "log::", "tracing::"] {
                assert!(
                    !production.contains(mac),
                    "{name} não pode usar {mac} em código de produção"
                );
            }
        }
    }
}
