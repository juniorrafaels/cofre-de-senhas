use crate::commands::vault::verify_current_password;
use crate::crypto::{self, KdfParams};
use crate::db;
use crate::state::VaultState;
use rand::seq::SliceRandom;
#[cfg(test)]
use rand::SeedableRng;
#[cfg(test)]
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use std::convert::TryFrom;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

pub const MAX_QUESTIONS: i64 = 20;
pub const RECOVERY_THRESHOLD: u8 = 3;
const RECOVERY_QUESTIONS_SHOWN: usize = 5;
const LOCKOUT_FAILURE_THRESHOLD: i64 = 5;
const LOCKOUT_MINUTES: i64 = 15;

#[cfg(test)]
const DEALER_CONTEXT: &[u8] = b"cofre-de-contas/security-questions-dealer/v1";
const DEK_CHECK_PLAINTEXT: &[u8] = b"vault-dek-check-v1";

fn generic_error() -> String {
    "Não foi possível concluir a operação.".to_string()
}

/// Mensagem devolvida por `add_security_question`/`update_security_question`. Mapeada para i18n
/// no frontend (`errors.securityQuestionsDeprecated`).
pub const DEPRECATED_MESSAGE: &str =
    "As perguntas de segurança foram descontinuadas por motivos de segurança. Gere uma Recovery Key.";

/// Mensagem para pedidos de recuperação malformados (mais respostas do que perguntas exibidas,
/// IDs repetidos, resposta absurdamente longa). Rejeitados ANTES de qualquer derivação de chave.
pub const INVALID_RECOVERY_REQUEST: &str = "Requisição de recuperação inválida.";

/// Tamanho máximo (em caracteres) aceito para uma resposta durante a recuperação.
const MAX_ANSWER_CHARS: usize = 1024;

/// Recalcula, de forma determinística, o share nº `share_index` (1-based) do segredo (a DEK).
/// Como a seed é derivada da própria DEK, o mesmo índice sempre produz o mesmo share.
///
/// Só existe em testes: criar/regravar shares foi desativado em produção (ver
/// `add_security_question`). Mesmo assim não pode entrar em pânico: o dealer do `sharks` gera no
/// máximo 255 shares (x = 1..=255 em GF(256)), então qualquer índice fora disso vira erro.
#[cfg(test)]
fn share_for_index(dek: &[u8; 32], share_index: i64) -> Result<Vec<u8>, String> {
    if !(1..=255).contains(&share_index) {
        return Err(generic_error());
    }
    let seed = crypto::derive_deterministic_seed(dek, DEALER_CONTEXT);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let sharks = Sharks(RECOVERY_THRESHOLD);
    let share = sharks
        .dealer_rng(dek.as_slice(), &mut rng)
        .nth((share_index - 1) as usize)
        .ok_or_else(generic_error)?;
    Ok(Vec::from(&share))
}

fn normalize_answer(answer: &str) -> Zeroizing<String> {
    Zeroizing::new(answer.trim().to_lowercase())
}

/// Lógica de criação herdada (antes usada por `add_security_question`), mantida só para os testes
/// montarem cofres "legados" que já tinham perguntas cadastradas — é assim que garantimos que
/// quem já tem perguntas continua conseguindo recuperar o cofre.
#[cfg(test)]
fn insert_legacy_question(
    conn: &rusqlite::Connection,
    dek: &[u8; 32],
    question: &str,
    share_index: i64,
    answer: &str,
    params: &KdfParams,
) -> Result<i64, String> {
    let share_bytes = share_for_index(dek, share_index)?;
    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let key = crypto::derive_key(&normalize_answer(answer), &salt, params).map_err(|_| generic_error())?;
    let wrapped = crypto::encrypt(&key, &share_bytes).map_err(|_| generic_error())?;
    let params_json = serde_json::to_string(params).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO security_questions (question, share_index, answer_salt, kdf_params, wrapped_share, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![question, share_index, salt, params_json, wrapped, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;
    Ok(conn.last_insert_rowid())
}

fn try_unwrap_share(answer: &str, salt: &[u8], params_json: &str, wrapped: &[u8]) -> Option<Vec<u8>> {
    let params: KdfParams = serde_json::from_str(params_json).ok()?;
    // `derive_key` já recusa parâmetros fora dos limites (ver `KdfParams::is_within_bounds`).
    let key = crypto::derive_key(&normalize_answer(answer), salt, &params).ok()?;
    crypto::decrypt(&key, wrapped).ok().map(|z| z.to_vec())
}

#[derive(Serialize)]
pub struct SecurityQuestionsSummary {
    pub count: i64,
    pub max_allowed: i64,
    pub min_required_for_recovery: u8,
}

#[tauri::command]
pub fn security_questions_summary(app: AppHandle) -> Result<SecurityQuestionsSummary, String> {
    let conn = db::open(&app)?;
    db::init_schema(&conn)?;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_questions", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    Ok(SecurityQuestionsSummary { count, max_allowed: MAX_QUESTIONS, min_required_for_recovery: RECOVERY_THRESHOLD })
}

/// DESCONTINUADO (auditoria de segurança): cada share do Shamir era protegida por uma chave
/// derivada de UMA única resposta, com sua própria tag AEAD — ou seja, quem obtiver o arquivo do
/// cofre consegue testar cada resposta offline de forma independente (custo do ataque = SOMA dos
/// dicionários, não o produto), e respostas a perguntas pessoais têm pouquíssima entropia. Além
/// disso o `sharks` 0.5 tem o RUSTSEC-2024-0398 (coeficientes enviesados) e parece sem manutenção.
/// Criar novas perguntas foi desativado; cofres que já têm perguntas continuam podendo usá-las
/// para recuperar o acesso (sem migração de formato), e o usuário pode removê-las.
///
/// A assinatura não recebe mais nenhum argumento de propósito: uma chamada antiga com
/// `question`/`answer`/`currentPassword` é aceita pelo IPC (chaves extras são ignoradas) e cai
/// direto neste erro, sem que a resposta seja processada.
#[tauri::command]
pub fn add_security_question() -> Result<(), String> {
    Err(DEPRECATED_MESSAGE.to_string())
}

/// DESCONTINUADO (ver `add_security_question`). Trocar a resposta re-embrulhava a share com uma
/// nova chave derivada só da nova resposta — o mesmo oráculo offline de antes, então foi
/// bloqueado. Editar só o texto da pergunta não re-embrulhava nada, mas também foi bloqueado por
/// simplicidade e para não incentivar o uso contínuo de um mecanismo descontinuado.
#[tauri::command]
pub fn update_security_question() -> Result<(), String> {
    Err(DEPRECATED_MESSAGE.to_string())
}

#[tauri::command]
pub fn delete_security_question(app: AppHandle, state: State<VaultState>, current_password: String, id: i64) -> Result<(), String> {
    let current_password = Zeroizing::new(current_password);
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    let conn = db::open(&app)?;
    verify_current_password(&conn, &current_password)?;
    conn.execute("DELETE FROM security_questions WHERE id = ?1", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
pub struct SecurityQuestionListItem {
    pub id: i64,
    pub question: String,
    pub share_index: i64,
    pub created_at: String,
}

/// Diferente de `get_recovery_questions` (usado durante o fluxo de recuperação, com o cofre
/// ainda BLOQUEADO, e que só mostra uma amostra de 5), este command lista TODAS as perguntas
/// cadastradas para a tela de gerenciamento em Configurações — por isso exige o cofre
/// desbloqueado. Nunca retorna `answer_salt`/`wrapped_share` (não há resposta nenhuma aqui).
#[tauri::command]
pub fn list_security_questions(app: AppHandle, state: State<VaultState>) -> Result<Vec<SecurityQuestionListItem>, String> {
    if !state.is_unlocked() {
        return Err("O cofre está bloqueado.".to_string());
    }
    let conn = db::open(&app)?;
    let mut stmt = conn
        .prepare("SELECT id, question, share_index, created_at FROM security_questions ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;
    let mapped = stmt
        .query_map([], |row| {
            Ok(SecurityQuestionListItem { id: row.get(0)?, question: row.get(1)?, share_index: row.get(2)?, created_at: row.get(3)? })
        })
        .map_err(|e| e.to_string())?;
    mapped.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct RecoveryQuestion {
    pub id: i64,
    pub question: String,
}

#[tauri::command]
pub fn get_recovery_questions(app: AppHandle) -> Result<Vec<RecoveryQuestion>, String> {
    let conn = db::open(&app)?;
    let mut stmt = conn.prepare("SELECT id, question FROM security_questions").map_err(|e| e.to_string())?;
    let mut all: Vec<RecoveryQuestion> = stmt
        .query_map([], |row| Ok(RecoveryQuestion { id: row.get(0)?, question: row.get(1)? }))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    let mut rng = rand::thread_rng();
    all.shuffle(&mut rng);
    all.truncate(RECOVERY_QUESTIONS_SHOWN);
    Ok(all)
}

#[derive(Deserialize)]
pub struct RecoveryAnswer {
    pub id: i64,
    pub answer: Zeroizing<String>,
}

#[derive(Serialize)]
pub struct RecoveryOutcome {
    pub success: bool,
    pub message: String,
}

fn recovery_lock_status(conn: &rusqlite::Connection) -> Result<(i64, Option<String>), String> {
    conn.query_row("SELECT failed_count, locked_until FROM recovery_attempts WHERE id = 1", [], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })
    .map_err(|e| e.to_string())
}

fn register_failed_attempt(conn: &rusqlite::Connection, failed_count: i64) -> Result<(), String> {
    let new_count = failed_count + 1;
    if new_count >= LOCKOUT_FAILURE_THRESHOLD {
        let locked_until = (chrono::Utc::now() + chrono::Duration::minutes(LOCKOUT_MINUTES)).to_rfc3339();
        conn.execute(
            "UPDATE recovery_attempts SET failed_count = 0, locked_until = ?1 WHERE id = 1",
            [locked_until],
        )
        .map_err(|e| e.to_string())?;
    } else {
        conn.execute("UPDATE recovery_attempts SET failed_count = ?1 WHERE id = 1", [new_count])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Resultado interno de uma tentativa de recuperação: separa a mensagem pública (`outcome`, o
/// que a WebView recebe) da DEK reconstruída (`dek`, que só o comando `#[tauri::command]` usa
/// para chamar `state.set_dek`). Extraído como função pura sobre `&Connection` (mesmo padrão já
/// usado por `verify_current_password`/`build_backup_payload`) para permitir testes automatizados
/// de todo o fluxo de recuperação por perguntas — incluindo o rate limiting de tentativas — sem
/// precisar de um `AppHandle`/`State` reais (ver seção "Recovery Key"/"Security Questions" do
/// pedido de validação final).
struct RecoveryAttemptResult {
    outcome: RecoveryOutcome,
    dek: Option<[u8; 32]>,
}

/// Valida o formato do pedido ANTES de qualquer Argon2: no máximo `RECOVERY_QUESTIONS_SHOWN`
/// respostas (o mesmo número que `get_recovery_questions` exibe), sem IDs repetidos e sem
/// respostas gigantes. Sem isso, um único pedido poderia testar respostas para todas as 20
/// perguntas de uma vez, ou repetir o mesmo ID várias vezes.
fn validate_recovery_request(answers: &[RecoveryAnswer]) -> Result<(), String> {
    if answers.len() > RECOVERY_QUESTIONS_SHOWN {
        return Err(INVALID_RECOVERY_REQUEST.to_string());
    }
    let mut ids = std::collections::HashSet::new();
    for answer in answers {
        if !ids.insert(answer.id) || answer.answer.chars().count() > MAX_ANSWER_CHARS {
            return Err(INVALID_RECOVERY_REQUEST.to_string());
        }
    }
    Ok(())
}

fn attempt_recovery_core(conn: &rusqlite::Connection, answers: &[RecoveryAnswer]) -> Result<RecoveryAttemptResult, String> {
    validate_recovery_request(answers)?;
    let (failed_count, locked_until) = recovery_lock_status(conn)?;
    if let Some(locked_until) = locked_until {
        if let Ok(locked_at) = chrono::DateTime::parse_from_rfc3339(&locked_until) {
            let remaining = locked_at.with_timezone(&chrono::Utc) - chrono::Utc::now();
            if remaining.num_seconds() > 0 {
                let minutes = (remaining.num_seconds() as f64 / 60.0).ceil() as i64;
                return Ok(RecoveryAttemptResult {
                    outcome: RecoveryOutcome {
                        success: false,
                        message: format!("Muitas tentativas incorretas. Tente novamente em {minutes} minuto(s)."),
                    },
                    dek: None,
                });
            }
            conn.execute("UPDATE recovery_attempts SET locked_until = NULL WHERE id = 1", [])
                .map_err(|e| e.to_string())?;
        }
    }

    let mut collected_shares: Vec<Share> = Vec::new();
    let mut seen_x: std::collections::HashSet<u8> = std::collections::HashSet::new();
    for answer in answers {
        let row: Option<(Vec<u8>, String, Vec<u8>)> = conn
            .query_row(
                "SELECT answer_salt, kdf_params, wrapped_share FROM security_questions WHERE id = ?1",
                [answer.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .ok();

        if let Some((salt, params_json, wrapped)) = row {
            if let Some(share_bytes) = try_unwrap_share(&answer.answer, &salt, &params_json, &wrapped) {
                if let Ok(share) = Share::try_from(share_bytes.as_slice()) {
                    // Duas shares com o mesmo x (só possível com um banco/backup forjado, já que
                    // `share_index` é UNIQUE) entrariam duplicadas na interpolação de Lagrange do
                    // `sharks` e corromperiam o resultado. Mantém só a primeira de cada x.
                    if seen_x.insert(share_bytes[0]) {
                        collected_shares.push(share);
                    }
                }
            }
        }
    }

    if collected_shares.len() < RECOVERY_THRESHOLD as usize {
        register_failed_attempt(conn, failed_count)?;
        return Ok(RecoveryAttemptResult {
            outcome: RecoveryOutcome {
                success: false,
                message: "Respostas insuficientes ou incorretas. Verifique e tente novamente.".to_string(),
            },
            dek: None,
        });
    }

    let sharks = Sharks(RECOVERY_THRESHOLD);
    let recovered = sharks.recover(collected_shares.iter());

    let dek_bytes = match recovered {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => {
            register_failed_attempt(conn, failed_count)?;
            return Ok(RecoveryAttemptResult {
                outcome: RecoveryOutcome {
                    success: false,
                    message: "Respostas insuficientes ou incorretas. Verifique e tente novamente.".to_string(),
                },
                dek: None,
            });
        }
    };
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);

    let dek_check: Option<Vec<u8>> = conn
        .query_row("SELECT dek_check FROM vault_meta WHERE id = 1", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if let Some(check) = dek_check {
        if !crypto::decrypt(&dek, &check).map(|p| p.as_slice() == DEK_CHECK_PLAINTEXT).unwrap_or(false) {
            register_failed_attempt(conn, failed_count)?;
            return Ok(RecoveryAttemptResult {
                outcome: RecoveryOutcome {
                    success: false,
                    message: "Respostas insuficientes ou incorretas. Verifique e tente novamente.".to_string(),
                },
                dek: None,
            });
        }
    }

    conn.execute("UPDATE recovery_attempts SET failed_count = 0, locked_until = NULL WHERE id = 1", [])
        .map_err(|e| e.to_string())?;

    // Auto-cura (Fase 2): a DEK também pode ser obtida por este caminho (sem nunca passar por
    // `unlock_vault`), então a migração precisa rodar aqui também.
    crate::migration::migrate_plaintext_account_fields(conn, &dek)?;

    Ok(RecoveryAttemptResult {
        outcome: RecoveryOutcome { success: true, message: "Identidade confirmada.".to_string() },
        dek: Some(dek),
    })
}

#[tauri::command]
pub fn attempt_vault_recovery(app: AppHandle, state: State<VaultState>, answers: Vec<RecoveryAnswer>) -> Result<RecoveryOutcome, String> {
    let conn = db::open(&app)?;
    attempt_recovery_into_state(&conn, &state, &answers)
}

/// Tentativa de recuperação + marcação da sessão como "aberta por recuperação" em caso de
/// sucesso (único estado em que `reset_master_password_after_recovery` é aceito).
fn attempt_recovery_into_state(conn: &rusqlite::Connection, state: &VaultState, answers: &[RecoveryAnswer]) -> Result<RecoveryOutcome, String> {
    let result = attempt_recovery_core(conn, answers)?;
    if let Some(dek) = result.dek {
        state.set_dek_from_recovery(dek);
    }
    Ok(result.outcome)
}

/// Redefine a senha mestra SEM pedir a atual — por isso só é aceito numa sessão aberta por
/// recuperação (`attempt_vault_recovery` ou `unlock_with_recovery_key`). Antes bastava haver
/// qualquer DEK em memória, então uma sessão comum (desbloqueada pela senha mestra) podia trocar
/// a senha sem reautenticar, contornando `change_master_password`.
#[tauri::command]
pub fn reset_master_password_after_recovery(app: AppHandle, state: State<VaultState>, new_password: String) -> Result<(), String> {
    let new_password = Zeroizing::new(new_password);
    let conn = db::open(&app)?;
    reset_master_password_core(&conn, &state, &new_password, &KdfParams::default())
}

pub(crate) fn reset_master_password_core(
    conn: &rusqlite::Connection,
    state: &VaultState,
    new_password: &Zeroizing<String>,
    new_params: &KdfParams,
) -> Result<(), String> {
    if new_password.len() < 8 {
        return Err("A nova senha mestra deve ter pelo menos 8 caracteres.".to_string());
    }
    let dek = state.with_recovery_dek(|dek| *dek).ok_or_else(|| "Identidade ainda não confirmada.".to_string())?;

    let new_salt = crypto::random_bytes(crypto::SALT_LEN);
    let new_kek = crypto::derive_key(new_password, &new_salt, new_params).map_err(|_| generic_error())?;
    let new_wrapped_dek = crypto::encrypt(&new_kek, &dek).map_err(|_| generic_error())?;
    let new_params_json = serde_json::to_string(new_params).map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE vault_meta SET kdf_salt = ?1, kdf_params = ?2, wrapped_dek = ?3 WHERE id = 1",
        rusqlite::params![new_salt, new_params_json, new_wrapped_dek],
    )
    .map_err(|e| e.to_string())?;

    // A sessão continua desbloqueada, mas deixa de ser "de recuperação": uma segunda troca de
    // senha agora exige `change_master_password` (com a senha atual).
    state.set_dek(dek);
    Ok(())
}

pub fn compute_dek_check(dek: &[u8; 32]) -> Result<Vec<u8>, String> {
    crypto::encrypt(dek, DEK_CHECK_PLAINTEXT).map_err(|_| "Falha ao preparar verificação da DEK.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parâmetros reduzidos apenas para os testes rodarem rápido (mesmo padrão de
    // `vault::tests::fixture_conn_with_password`/`crypto::tests::test_params`); produção usa
    // `KdfParams::default()`.
    fn test_params() -> KdfParams {
        KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 }
    }

    /// Monta um cofre sintético completo (vault_meta + N perguntas de segurança reais, cifradas
    /// com o mesmo Shamir Secret Sharing usado em produção) para exercitar `attempt_recovery_core`
    /// de ponta a ponta, sem precisar de `AppHandle`/`State` reais — mesmo padrão já estabelecido
    /// em `vault::tests`/`properties::tests`. Retorna `(conn, dek, [(id, resposta_correta); N])`.
    fn fixture_vault_with_questions(answers: &[&str]) -> (rusqlite::Connection, [u8; 32], Vec<(i64, String)>) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();

        let dek = [7u8; 32];
        let dek_check = compute_dek_check(&dek).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                crypto::random_bytes(crypto::SALT_LEN),
                serde_json::to_string(&test_params()).unwrap(),
                // wrapped_dek não é usado por este fluxo de recuperação (só pela senha mestra),
                // mas a coluna é NOT NULL — qualquer ciphertext válido serve de placeholder aqui.
                crypto::encrypt(&dek, &dek).unwrap(),
                dek_check,
                db::now_iso(),
            ],
        )
        .unwrap();

        let mut ids = Vec::new();
        for (index, answer) in answers.iter().enumerate() {
            // Mesma lógica de criação que existia em `add_security_question` (hoje desativado),
            // com `test_params()` para o teste não levar ~300-500ms por pergunta.
            let id = insert_legacy_question(&conn, &dek, &format!("Pergunta {index}?"), (index + 1) as i64, answer, &test_params()).unwrap();
            ids.push((id, answer.to_string()));
        }

        conn.execute("INSERT OR IGNORE INTO recovery_attempts (id, failed_count, locked_until) VALUES (1, 0, NULL)", []).ok();
        (conn, dek, ids)
    }

    fn answer_of(ids: &[(i64, String)], index: usize, text: &str) -> RecoveryAnswer {
        RecoveryAnswer { id: ids[index].0, answer: Zeroizing::new(text.to_string()) }
    }

    // Seção 18/54 do pedido de validação final: 3 respostas corretas (de N >= 3 perguntas
    // cadastradas) devem reconstruir exatamente a mesma DEK que protege as senhas/notes/2FA do
    // cofre — não uma DEK "parecida" nem um bypass que aceite qualquer coisa.
    #[test]
    fn correct_answers_reconstruct_the_real_dek() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];

        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(result.outcome.success);
        assert_eq!(result.dek, Some(dek), "a DEK reconstruída via perguntas deve ser IDÊNTICA à DEK real do cofre");
    }

    // Respostas normalizadas (trim + lowercase) — capitalização/espaços não podem impedir uma
    // recuperação legítima.
    #[test]
    fn answers_are_normalized_before_checking() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "  SÃO PAULO  "), answer_of(&ids, 1, "rex"), answer_of(&ids, 2, "AZUL")];

        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(result.outcome.success);
        assert_eq!(result.dek, Some(dek));
    }

    // Seção 18 do pedido: resposta errada é rejeitada de forma limpa — sem reconstruir uma DEK
    // parcial/incorreta, sem corromper `recovery_attempts`, sem mudar `vault_meta`.
    #[test]
    fn wrong_answer_is_rejected_cleanly_without_altering_state() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "Rio de Janeiro"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];

        let dek_check_before: Vec<u8> =
            conn.query_row("SELECT dek_check FROM vault_meta WHERE id = 1", [], |r| r.get(0)).unwrap();

        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(!result.outcome.success);
        assert!(result.dek.is_none());

        let dek_check_after: Vec<u8> =
            conn.query_row("SELECT dek_check FROM vault_meta WHERE id = 1", [], |r| r.get(0)).unwrap();
        assert_eq!(dek_check_before, dek_check_after, "uma tentativa incorreta não pode alterar vault_meta");
    }

    // Respostas parcialmente corretas (só 2 de 3, abaixo do limiar Shamir) devem falhar do mesmo
    // jeito que todas erradas — não existe "quase recuperado".
    #[test]
    fn partially_correct_answers_below_threshold_are_rejected() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Verde")];

        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(!result.outcome.success, "2 de 3 corretas (abaixo do limiar de 3) não pode recuperar o cofre");
        assert!(result.dek.is_none());
    }

    // Seção 18/24 do pedido: 5 tentativas incorretas seguidas devem bloquear tentativas
    // subsequentes por um tempo (mensagem explícita de "tente novamente em N minutos"), mesmo que
    // a 6a tentativa use as respostas CORRETAS — o lockout é por tempo, não descontado por acerto.
    #[test]
    fn five_failed_attempts_lock_out_even_a_subsequent_correct_attempt() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let wrong = vec![answer_of(&ids, 0, "errada"), answer_of(&ids, 1, "errada"), answer_of(&ids, 2, "errada")];

        for attempt in 1..=5 {
            let result = attempt_recovery_core(&conn, &wrong).unwrap();
            assert!(!result.outcome.success, "tentativa {attempt} deveria falhar (resposta errada)");
        }

        let (failed_count, locked_until) = recovery_lock_status(&conn).unwrap();
        assert_eq!(failed_count, 0, "o contador é zerado no momento em que o lockout começa");
        assert!(locked_until.is_some(), "5 falhas consecutivas devem ativar o lockout temporário");

        let correct = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];
        let result = attempt_recovery_core(&conn, &correct).unwrap();
        assert!(!result.outcome.success, "mesmo respostas corretas devem ser recusadas durante o lockout");
        assert!(result.outcome.message.contains("Tente novamente"));
        assert!(result.dek.is_none());
    }

    // Depois que `locked_until` já passou (simulado escrevendo uma data no passado — equivalente
    // a esperar os 15 minutos de verdade), a próxima tentativa correta deve funcionar normalmente.
    #[test]
    fn lockout_expires_and_correct_answers_work_again_after_the_window() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let wrong = vec![answer_of(&ids, 0, "errada"), answer_of(&ids, 1, "errada"), answer_of(&ids, 2, "errada")];
        for _ in 1..=5 {
            attempt_recovery_core(&conn, &wrong).unwrap();
        }
        let (_, locked_until) = recovery_lock_status(&conn).unwrap();
        assert!(locked_until.is_some());

        // Simula o relógio já ter passado do horário de desbloqueio (equivalente a "restart" após
        // esperar a janela, seção 18 do pedido) sem precisar dormir 15 minutos de verdade no teste.
        let past = (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339();
        conn.execute("UPDATE recovery_attempts SET locked_until = ?1 WHERE id = 1", [past]).unwrap();

        let correct = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];
        let result = attempt_recovery_core(&conn, &correct).unwrap();
        assert!(result.outcome.success, "depois que a janela de lockout expira, respostas corretas devem funcionar de novo");
        assert_eq!(result.dek, Some(dek));
    }

    // Seção 19 do pedido ("Master Password Change"), aplicado ao caminho de recuperação: depois
    // de reconstruir a DEK via perguntas e redefinir a senha mestra, a senha ANTIGA não pode mais
    // abrir o cofre, a NOVA deve funcionar, e a DEK (logo, todos os segredos já cifrados com ela)
    // continua exatamente a mesma — nenhuma recriptografia/corrupção.
    #[test]
    fn reset_master_password_after_recovery_invalidates_old_password_and_keeps_the_same_dek() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];
        let recovered = attempt_recovery_core(&conn, &answers).unwrap();
        let recovered_dek = recovered.dek.expect("recuperação deveria ter sucesso neste teste");
        assert_eq!(recovered_dek, dek);

        // Mesma lógica de `reset_master_password_after_recovery`, exercitada diretamente sobre a
        // DEK recuperada (sem precisar de `State`/`AppHandle` reais).
        let new_password = Zeroizing::new("nova-senha-mestra-XSS_TEST".to_string());
        let new_salt = crypto::random_bytes(crypto::SALT_LEN);
        let new_params = test_params();
        let new_kek = crypto::derive_key(&new_password, &new_salt, &new_params).unwrap();
        let new_wrapped_dek = crypto::encrypt(&new_kek, &recovered_dek).unwrap();
        conn.execute(
            "UPDATE vault_meta SET kdf_salt = ?1, kdf_params = ?2, wrapped_dek = ?3 WHERE id = 1",
            rusqlite::params![new_salt, serde_json::to_string(&new_params).unwrap(), new_wrapped_dek],
        )
        .unwrap();

        // Senha antiga: nunca existiu de verdade neste fixture (a recuperação não passa pela
        // senha mestra), mas qualquer senha candidata que não seja a nova deve falhar.
        assert!(crate::commands::vault::verify_current_password(&conn, &Zeroizing::new("senha-antiga-qualquer".to_string())).is_err());
        // Senha nova funciona e devolve exatamente a mesma DEK que já protegia os dados.
        let dek_after = crate::commands::vault::verify_current_password(&conn, &new_password).unwrap();
        assert_eq!(dek_after, dek, "trocar a senha mestra após recuperação não pode mudar a DEK nem corromper os dados já cifrados");
    }

    // ---------------------------------------------------------------------------------------
    // Descontinuação das perguntas de segurança + sessão de recuperação (auditoria, itens A/B)
    // ---------------------------------------------------------------------------------------

    /// Mesmo cofre sintético de `fixture_vault_with_questions`, mas com um `wrapped_dek` real
    /// para `master_password` — necessário para exercitar desbloqueio normal vs. recuperação.
    fn fixture_with_master_password(master_password: &str, answers: &[&str]) -> (rusqlite::Connection, [u8; 32], Vec<(i64, String)>) {
        let (conn, dek, ids) = fixture_vault_with_questions(answers);
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let kek = crypto::derive_key(master_password, &salt, &test_params()).unwrap();
        conn.execute(
            "UPDATE vault_meta SET kdf_salt = ?1, kdf_params = ?2, wrapped_dek = ?3 WHERE id = 1",
            rusqlite::params![salt, serde_json::to_string(&test_params()).unwrap(), crypto::encrypt(&kek, &dek).unwrap()],
        )
        .unwrap();
        (conn, dek, ids)
    }

    fn correct_three(ids: &[(i64, String)]) -> Vec<RecoveryAnswer> {
        (0..3).map(|i| answer_of(ids, i, &ids[i].1.clone())).collect()
    }

    fn failed_count(conn: &rusqlite::Connection) -> i64 {
        recovery_lock_status(conn).unwrap().0
    }

    #[test]
    fn adding_or_updating_security_questions_is_rejected_as_deprecated() {
        assert_eq!(add_security_question().unwrap_err(), DEPRECATED_MESSAGE);
        assert_eq!(update_security_question().unwrap_err(), DEPRECATED_MESSAGE);
    }

    #[test]
    fn share_index_out_of_range_returns_error_instead_of_panicking() {
        let dek = [1u8; 32];
        for bad in [0, -1, 256, 10_000, i64::MAX, i64::MIN] {
            assert!(share_for_index(&dek, bad).is_err(), "índice {bad} deveria virar erro, não pânico");
        }
        assert!(share_for_index(&dek, 1).is_ok());
        assert!(share_for_index(&dek, 255).is_ok());
    }

    #[test]
    fn legacy_vault_with_five_questions_recovers_with_three_correct_and_two_wrong() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["um", "dois", "três", "quatro", "cinco"]);
        let answers = vec![
            answer_of(&ids, 0, "um"),
            answer_of(&ids, 1, "errada"),
            answer_of(&ids, 2, "três"),
            answer_of(&ids, 3, "errada"),
            answer_of(&ids, 4, "cinco"),
        ];
        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(result.outcome.success);
        assert_eq!(result.dek, Some(dek));
    }

    #[test]
    fn more_answers_than_presented_questions_are_rejected_before_any_kdf() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["a", "b", "c", "d", "e", "f"]);
        let answers: Vec<RecoveryAnswer> = (0..6).map(|i| answer_of(&ids, i, &ids[i].1.clone())).collect();
        let err = attempt_recovery_core(&conn, &answers).err().expect("6 respostas (> 5 exibidas) devem ser recusadas");
        assert_eq!(err, INVALID_RECOVERY_REQUEST);
        assert_eq!(failed_count(&conn), 0, "pedido malformado não chega a ser uma tentativa");
    }

    #[test]
    fn duplicate_question_ids_are_rejected() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let answers = vec![answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 0, "São Paulo"), answer_of(&ids, 1, "Rex")];
        assert_eq!(attempt_recovery_core(&conn, &answers).err().unwrap(), INVALID_RECOVERY_REQUEST);
    }

    #[test]
    fn oversized_answer_is_rejected_before_any_kdf() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let huge = "x".repeat(MAX_ANSWER_CHARS + 1);
        let answers = vec![answer_of(&ids, 0, &huge), answer_of(&ids, 1, "Rex"), answer_of(&ids, 2, "Azul")];
        assert_eq!(attempt_recovery_core(&conn, &answers).err().unwrap(), INVALID_RECOVERY_REQUEST);
    }

    // `share_index` é UNIQUE no schema, mas o x de cada share vem do conteúdo cifrado — um banco/
    // backup forjado (com respostas escolhidas pelo próprio atacante) pode ter duas linhas cujas
    // shares têm o MESMO x. Elas não podem contar como duas shares distintas nem derrubar o app.
    #[test]
    fn shares_with_the_same_x_coordinate_do_not_panic_or_count_twice() {
        let (conn, dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex"]);
        let share_x1 = share_for_index(&dek, 1).unwrap();
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let key = crypto::derive_key(&normalize_answer("Outra"), &salt, &test_params()).unwrap();
        conn.execute(
            "INSERT INTO security_questions (question, share_index, answer_salt, kdf_params, wrapped_share, created_at) VALUES ('Forjada?', 3, ?1, ?2, ?3, 'now')",
            rusqlite::params![salt, serde_json::to_string(&test_params()).unwrap(), crypto::encrypt(&key, &share_x1).unwrap()],
        )
        .unwrap();
        let dup_id = conn.last_insert_rowid();
        let answers = vec![
            answer_of(&ids, 0, "São Paulo"),
            answer_of(&ids, 1, "Rex"),
            RecoveryAnswer { id: dup_id, answer: Zeroizing::new("Outra".to_string()) },
        ];
        let result = attempt_recovery_core(&conn, &answers).unwrap();
        assert!(!result.outcome.success, "só 2 shares distintas (x repetido) — abaixo do limiar");
        assert!(result.dek.is_none());
    }

    #[test]
    fn failed_recovery_does_not_unlock_the_state() {
        let (conn, _dek, ids) = fixture_vault_with_questions(&["São Paulo", "Rex", "Azul"]);
        let state = VaultState::new();
        let wrong = vec![answer_of(&ids, 0, "x"), answer_of(&ids, 1, "y"), answer_of(&ids, 2, "z")];
        let outcome = attempt_recovery_into_state(&conn, &state, &wrong).unwrap();
        assert!(!outcome.success);
        assert!(!state.is_unlocked());
    }

    // Item B: uma sessão aberta normalmente pela senha mestra NÃO pode trocar a senha mestra sem
    // informar a atual — antes bastava a DEK estar em memória.
    #[test]
    fn normal_unlock_cannot_use_reset_after_recovery() {
        let (conn, _dek, _ids) = fixture_with_master_password("senha-mestra-antiga", &["São Paulo", "Rex", "Azul"]);
        let state = VaultState::new();
        crate::commands::vault::unlock_vault_core(&conn, &state, &Zeroizing::new("senha-mestra-antiga".to_string())).unwrap();
        assert!(state.is_unlocked());

        let err = reset_master_password_core(&conn, &state, &Zeroizing::new("nova-senha-mestra".to_string()), &test_params()).unwrap_err();
        assert_eq!(err, "Identidade ainda não confirmada.");

        // Nada mudou: a senha antiga continua sendo a única que abre o cofre.
        assert!(verify_current_password(&conn, &Zeroizing::new("senha-mestra-antiga".to_string())).is_ok());
        assert!(verify_current_password(&conn, &Zeroizing::new("nova-senha-mestra".to_string())).is_err());
    }

    #[test]
    fn locked_vault_cannot_use_reset_after_recovery() {
        let (conn, _dek, ids) = fixture_with_master_password("senha-mestra-antiga", &["São Paulo", "Rex", "Azul"]);
        let state = VaultState::new();
        assert!(attempt_recovery_into_state(&conn, &state, &correct_three(&ids)).unwrap().success);
        state.clear(); // o que `lock_vault`/auto-lock/lock nativo fazem
        let err = reset_master_password_core(&conn, &state, &Zeroizing::new("nova-senha-mestra".to_string()), &test_params()).unwrap_err();
        assert_eq!(err, "Identidade ainda não confirmada.");
    }

    #[test]
    fn questions_recovery_then_reset_then_unlock_with_new_password_preserves_dek_and_data() {
        let (conn, dek, ids) = fixture_with_master_password("senha-mestra-antiga", &["São Paulo", "Rex", "Azul"]);
        let secret_ciphertext = crypto::encrypt_to_base64(&dek, "SECURITY_TEST_SECRET_55123").unwrap();

        let state = VaultState::new();
        let outcome = attempt_recovery_into_state(&conn, &state, &correct_three(&ids)).unwrap();
        assert!(outcome.success);
        assert_eq!(state.unlock_method(), Some(crate::state::UnlockMethod::Recovery));

        reset_master_password_core(&conn, &state, &Zeroizing::new("nova-senha-mestra".to_string()), &test_params()).unwrap();
        assert_eq!(state.unlock_method(), Some(crate::state::UnlockMethod::MasterPassword), "o flag de recuperação é consumido pelo reset");
        assert!(
            reset_master_password_core(&conn, &state, &Zeroizing::new("outra-senha-qualquer".to_string()), &test_params()).is_err(),
            "um segundo reset sem senha atual não pode ser aceito",
        );

        state.clear();
        let fresh = VaultState::new();
        assert!(crate::commands::vault::unlock_vault_core(&conn, &fresh, &Zeroizing::new("senha-mestra-antiga".to_string())).is_err());
        crate::commands::vault::unlock_vault_core(&conn, &fresh, &Zeroizing::new("nova-senha-mestra".to_string())).unwrap();
        assert_eq!(fresh.with_dek(|d| *d), Some(dek));
        let plaintext = fresh.with_dek(|d| crypto::decrypt_from_base64(d, &secret_ciphertext)).unwrap().unwrap();
        assert_eq!(plaintext, "SECURITY_TEST_SECRET_55123");
    }
}
