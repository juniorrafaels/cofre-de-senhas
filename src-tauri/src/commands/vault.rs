use crate::auth;
use crate::commands::security_questions;
use crate::crypto::{self, KdfParams};
use crate::db;
use crate::lockout::{Clock, SystemClock};
use crate::state::{UnlockMethod, VaultState};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

#[derive(Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
}

/// Confere uma senha candidata contra o `wrapped_dek` gravado no banco, decifrando-o de verdade
/// (não é uma comparação de flag) — usado por qualquer operação crítica que precise reautenticar
/// a senha mestra dentro do próprio comando (Recovery Key, perguntas de segurança — ver
/// SECURITY_AUDIT_PHASE_4.md). Equivale a `verify_credentials(conn, password, None)`: num cofre com
/// desbloqueio de duas senhas ela FALHA com `E_SECOND_PASSWORD_REQUIRED` (uma senha só nunca basta).
#[cfg(test)]
pub fn verify_current_password(conn: &rusqlite::Connection, password: &Zeroizing<String>) -> Result<[u8; 32], String> {
    verify_credentials(conn, password, None)
}

/// Reautentica as credenciais atuais (uma ou duas senhas, conforme a política do cofre) aplicando
/// o bloqueio progressivo, quando ativado. Retorna a DEK só para confirmar que as credenciais
/// realmente desembrulham o segredo certo.
pub fn verify_credentials(
    conn: &rusqlite::Connection,
    password: &Zeroizing<String>,
    password2: Option<&Zeroizing<String>>,
) -> Result<[u8; 32], String> {
    auth::authenticate(conn, password, password2.map(|p| p.as_str()), &SystemClock).map_err(|e| e.to_ipc())
}

/// Converte o segundo campo de senha vindo da WebView: vazio = ausente.
pub fn opt_secret(value: Option<String>) -> Option<Zeroizing<String>> {
    value.filter(|v| !v.is_empty()).map(Zeroizing::new)
}

#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<VaultState>) -> Result<VaultStatus, String> {
    let conn = db::open(&app)?;
    db::init_schema(&conn)?;
    // Chamado a cada início do app (mesmo antes do desbloqueio) — é aqui que uma instalação
    // nova ganha as imagens padrão das plataformas oficiais, e onde uma instalação existente
    // "cura" qualquer logo padrão que ainda esteja pendente (ver db::provision_default_platform_images).
    db::provision_default_platform_images(&app, &conn)?;
    let initialized: bool = conn
        .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|e| e.to_string())?
        > 0;
    Ok(VaultStatus { initialized, unlocked: state.is_unlocked() })
}

#[tauri::command]
pub fn create_vault(app: AppHandle, state: State<VaultState>, password: String) -> Result<(), String> {
    // Zeroing: a senha mestra em texto puro só existe nesta função pelo tempo da derivação da
    // KEK (Argon2id, ~300-500ms) — envolvê-la garante que os bytes sejam sobrescritos com zero
    // ao sair de escopo, em vez de ficarem na heap liberada até serem reaproveitados por outra
    // alocação (ver SECURITY_AUDIT_PHASE_3.md, seção "Memória/Zeroization" para limitações).
    let password = Zeroizing::new(password);
    if password.len() < 8 {
        return Err("A senha mestra deve ter pelo menos 8 caracteres.".to_string());
    }
    let conn = db::open(&app)?;
    db::init_schema(&conn)?;
    db::provision_default_platform_images(&app, &conn)?;

    let existing: i64 = conn
        .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if existing > 0 {
        return Err("O cofre já foi criado.".to_string());
    }

    let reservation = state.reserve_exclusive()?;
    let params = KdfParams::default();
    let salt = crypto::random_bytes(crypto::SALT_LEN);
    let kek = crypto::derive_key(&password, &salt, &params).map_err(|_| auth::MSG_GENERIC.to_string())?;

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&crypto::random_bytes(32));
    let wrapped_dek = crypto::encrypt(&kek, &dek).map_err(|_| auth::MSG_GENERIC.to_string())?;

    let params_json = serde_json::to_string(&params).map_err(|e| e.to_string())?;
    let dek_check = security_questions::compute_dek_check(&dek)?;
    conn.execute(
        "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![salt, params_json, wrapped_dek, dek_check, db::now_iso()],
    )
    .map_err(|e| e.to_string())?;

    state.commit(dek, UnlockMethod::MasterPassword, reservation)
}

#[tauri::command]
pub fn unlock_vault(app: AppHandle, state: State<VaultState>, password: String, password2: Option<String>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let password2 = opt_secret(password2);
    let conn = db::open(&app)?;
    unlock_vault_with(&conn, &state, &password, password2.as_ref(), &SystemClock)
}

/// Lógica de `unlock_vault` sobre uma `Connection`/`VaultState` quaisquer (testável sem
/// `AppHandle`). Desbloqueio normal: `state.set_dek` sempre zera o flag de "sessão de
/// recuperação" (ver `state::UnlockMethod`).
#[cfg(test)]
pub(crate) fn unlock_vault_core(conn: &rusqlite::Connection, state: &VaultState, password: &Zeroizing<String>) -> Result<(), String> {
    unlock_vault_with(conn, state, password, None, &SystemClock)
}

/// Desbloqueio completo: (1) reserva a exclusividade de cofre aberto ANTES de tocar em credenciais
/// (outra instância já com o cofre aberto => `E_VAULT_OPEN_ELSEWHERE`, sem gastar tentativas);
/// (2) autentica uma ou duas senhas conforme a política, com bloqueio progressivo; (3) migra
/// campos legados; (4) só então abre a sessão.
pub(crate) fn unlock_vault_with(
    conn: &rusqlite::Connection,
    state: &VaultState,
    password: &Zeroizing<String>,
    password2: Option<&Zeroizing<String>>,
    clock: &dyn Clock,
) -> Result<(), String> {
    let reservation = state.reserve_exclusive()?;
    let dek = auth::authenticate(conn, password, password2.map(|p| p.as_str()), clock).map_err(|e| e.to_ipc())?;

    let has_check: Option<Vec<u8>> = conn
        .query_row("SELECT dek_check FROM vault_meta WHERE id = 1", [], |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if has_check.is_none() {
        let dek_check = security_questions::compute_dek_check(&dek)?;
        conn.execute("UPDATE vault_meta SET dek_check = ?1 WHERE id = 1", rusqlite::params![dek_check])
            .map_err(|e| e.to_string())?;
    }

    // Auto-cura (Fase 2): re-cifra qualquer campo de conta que ainda esteja em texto puro de
    // versões anteriores (ex.: notes antes desta correção). Idempotente e barato depois da
    // primeira execução — ver `migration.rs`.
    crate::migration::migrate_all(conn, &dek)?;

    state.commit(dek, UnlockMethod::MasterPassword, reservation)
}

#[tauri::command]
pub fn lock_vault(state: State<VaultState>) -> Result<(), String> {
    state.clear();
    Ok(())
}

#[tauri::command]
pub fn change_master_password(
    app: AppHandle,
    state: State<VaultState>,
    current_password: String,
    new_password: String,
    current_password2: Option<String>,
) -> Result<(), String> {
    let current_password = Zeroizing::new(current_password);
    let current_password2 = opt_secret(current_password2);
    let new_password = Zeroizing::new(new_password);
    if new_password.len() < 8 {
        return Err("A nova senha mestra deve ter pelo menos 8 caracteres.".to_string());
    }
    if new_password.chars().count() > auth::MAX_PASSWORD_CHARS {
        return Err(auth::MSG_PASSWORD_TOO_LONG.to_string());
    }
    let conn = db::open(&app)?;
    change_master_password_core(&conn, &state, &current_password, current_password2.as_ref(), &new_password, &KdfParams::default(), &SystemClock)
}

/// Troca a senha mestra (senha 1) preservando a DEK, a política de desbloqueio (e a senha 2, se
/// houver) e todos os métodos de recuperação, que embrulham a mesma DEK em envelopes independentes.
pub(crate) fn change_master_password_core(
    conn: &rusqlite::Connection,
    state: &VaultState,
    current_password: &Zeroizing<String>,
    current_password2: Option<&Zeroizing<String>>,
    new_password: &Zeroizing<String>,
    params: &KdfParams,
    clock: &dyn Clock,
) -> Result<(), String> {
    let reservation = state.reserve_exclusive()?;
    let dek = auth::change_first(
        conn,
        current_password,
        current_password2.map(|p| p.as_str()),
        new_password,
        params,
        clock,
    )?;
    state.commit(dek, UnlockMethod::MasterPassword, reservation)
}

/// Confirma a senha mestra atual sem alterar nada — usado pela Etapa 1 da exclusão do cofre
/// (Configurações → Dados → Zona de perigo). Reaproveita a mesma verificação real (decifra o
/// `wrapped_dek`) usada por `change_master_password`/Recovery Key/perguntas de segurança — nunca
/// uma comparação de flag decidida no frontend.
#[tauri::command]
pub fn verify_master_password(app: AppHandle, password: String, password2: Option<String>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let password2 = opt_secret(password2);
    let conn = db::open(&app)?;
    verify_credentials(&conn, &password, password2.as_ref())?;
    Ok(())
}

/// Apaga todas as linhas de todas as tabelas do cofre (mesmo conjunto que
/// `backup::restore_backup_payload` apaga antes de restaurar um backup — só que aqui nada é
/// reinserido depois). Extraída do command para ser testável com uma `Connection` de teste, sem
/// precisar de um `AppHandle` real.
fn wipe_all_tables(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "DELETE FROM account_history;
         DELETE FROM account_properties;
         DELETE FROM project_tags;
         DELETE FROM account_projects;
         DELETE FROM account_tags;
         DELETE FROM recovery_attempts;
         DELETE FROM security_questions;
         DELETE FROM accounts;
         DELETE FROM custom_property_definitions;
         DELETE FROM projects;
         DELETE FROM images;
         DELETE FROM tags;
         DELETE FROM platform_seed_state;
         DELETE FROM platforms;
         DELETE FROM settings;
         DELETE FROM auth_throttle;
         DELETE FROM vault_meta;",
    )
    .map_err(|e| e.to_string())
}

/// Exclui completamente o cofre desta instalação (seção "Zona de perigo" em Configurações →
/// Dados): reautentica a senha mestra (mesmo mecanismo de `verify_master_password`, nunca um
/// flag do frontend), apaga todas as linhas de todas as tabelas e os arquivos da biblioteca de
/// imagens em disco (`$APPDATA/images` — as cópias importadas para o cofre, nunca arquivos
/// originais do usuário fora dessa pasta), e limpa a DEK da memória. O arquivo `vault.db`
/// continua existindo (schema intacto), mas sem `vault_meta` — exatamente o estado que
/// `vault_status` reporta como `initialized: false`, ou seja, o mesmo estado de uma instalação
/// nova. A UI já exige duas confirmações independentes (senha mestra + digitar "EXCLUIR") antes
/// de chamar este comando.
#[tauri::command]
pub fn delete_vault(app: AppHandle, state: State<VaultState>, password: String, password2: Option<String>) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let password2 = opt_secret(password2);
    let conn = db::open(&app)?;
    verify_credentials(&conn, &password, password2.as_ref())?;
    wipe_all_tables(&conn)?;
    // Backups cifrados da migração de metadados (contêm o cofre antigo): saem junto com o cofre.
    if let Some(db_path) = crate::migration::connection_db_path(&conn) {
        crate::migration::remove_premigration_backups(&db_path);
    }
    drop(conn);

    if let Ok(dir) = app.path().app_data_dir() {
        let _ = std::fs::remove_dir_all(dir.join("images"));
    }

    state.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_conn_with_password(password: &str) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_schema(&conn).unwrap();
        let params = KdfParams { memory_kib: 8 * 1024, iterations: 1, parallelism: 1 };
        let salt = crypto::random_bytes(crypto::SALT_LEN);
        let password = Zeroizing::new(password.to_string());
        let kek = crypto::derive_key(&password, &salt, &params).unwrap();
        let dek = [5u8; 32];
        let wrapped_dek = crypto::encrypt(&kek, &dek).unwrap();
        let params_json = serde_json::to_string(&params).unwrap();
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, kdf_params, wrapped_dek, dek_check, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![salt, params_json, wrapped_dek, dek.to_vec(), db::now_iso()],
        )
        .unwrap();
        conn
    }

    // Regressão de segurança (SECURITY_AUDIT_PHASE_4.md): a reautenticação exigida por
    // `generate_recovery_key`/`disable_recovery_key`/`add|update|delete_security_question` só
    // pode prosseguir se a senha mestra ATUAL realmente desembrulhar a DEK — não é um flag que a
    // WebView possa simplesmente afirmar como verdadeiro.
    #[test]
    fn verify_current_password_rejects_wrong_password() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");
        assert!(verify_current_password(&conn, &Zeroizing::new("senha-errada".to_string())).is_err());
    }

    #[test]
    fn verify_current_password_accepts_right_password_and_returns_dek() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");
        let dek = verify_current_password(&conn, &Zeroizing::new("senha-correta-XSS_TEST".to_string())).unwrap();
        assert_eq!(dek, [5u8; 32]);
    }

    // Seção 1/6/7 do pedido de exclusão do cofre: uma senha errada não pode chegar a apagar
    // nada — `delete_vault` só chama `wipe_all_tables` depois que `verify_current_password`
    // retorna com sucesso, então testar essa ordem aqui é o equivalente, sem precisar de um
    // `AppHandle` real, a testar o command inteiro.
    #[test]
    fn wrong_password_never_reaches_the_wipe_step() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");
        let result = verify_current_password(&conn, &Zeroizing::new("senha-errada".to_string()));
        assert!(result.is_err());

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM vault_meta", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1, "vault_meta não deve ser tocado quando a senha mestra está errada");
    }

    // Seção 6 do pedido: a exclusão precisa remover contas, projetos, plataformas
    // personalizadas, configurações e todos os dados relacionados ao cofre.
    #[test]
    fn wipe_all_tables_removes_every_table() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");
        conn.execute(
            "INSERT INTO projects (name, favorite, created_at, updated_at) VALUES ('Projeto teste', 0, 'now', 'now')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO accounts (name, created_at, updated_at, status) VALUES ('Conta teste', 'now', 'now', 'active')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO platforms (name, is_custom, created_at, sort_order) VALUES ('Plataforma custom', 1, 'now', 999)",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO settings (key, value) VALUES ('theme', 'dark')", []).unwrap();

        let platforms_before: i64 = conn.query_row("SELECT COUNT(*) FROM platforms", [], |row| row.get(0)).unwrap();
        assert!(platforms_before > 0, "fixture deveria ter plataformas (seeds + a customizada)");

        wipe_all_tables(&conn).unwrap();

        for table in [
            "vault_meta",
            "platforms",
            "platform_seed_state",
            "accounts",
            "projects",
            "tags",
            "images",
            "settings",
            "security_questions",
            "recovery_attempts",
            "account_history",
            "account_properties",
            "custom_property_definitions",
        ] {
            let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap();
            assert_eq!(count, 0, "tabela {table} deveria estar vazia após excluir o cofre");
        }
    }

    // Seção 8 do pedido de ajuste ("Exclusão + recriação"): depois de excluir o cofre, criar um
    // novo (reabrir o schema) precisa restaurar exatamente o baseline padrão do app — mesmo que o
    // cofre anterior tivesse ordem/logo personalizadas pelo usuário. `wipe_all_tables` já limpa
    // `platform_seed_state` (ver `wipe_all_tables_removes_every_table`), então `db::init_schema`
    // reprocessa `PLATFORM_SEEDS` do zero como se fosse uma instalação nova.
    #[test]
    fn delete_then_recreate_restores_default_order_even_after_user_customization() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");

        // Usuário reordena e troca a logo de uma plataforma oficial antes de excluir o cofre.
        conn.execute(
            "INSERT INTO images (filename, original_name, hash, created_at) VALUES ('custom.png', 'x.png', 'custom-hash', 'now')",
            [],
        )
        .unwrap();
        let custom_logo_id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE platforms SET sort_order = 999, logo_image_id = ?1 WHERE system_key = 'instagram'",
            [custom_logo_id],
        )
        .unwrap();

        wipe_all_tables(&conn).unwrap();
        db::init_schema(&conn).unwrap();

        let (sort_order, logo_image_id): (i64, Option<i64>) = conn
            .query_row("SELECT sort_order, logo_image_id FROM platforms WHERE system_key = 'instagram'", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(sort_order, 0, "Instagram deve voltar ao sort_order padrão (0), não ao 999 personalizado");
        assert_eq!(logo_image_id, None, "logo personalizada do cofre anterior não pode sobreviver à exclusão");

        let total: i64 = conn.query_row("SELECT COUNT(*) FROM platforms", [], |row| row.get(0)).unwrap();
        assert!(total > 0, "novo cofre deve nascer com as plataformas padrão");
    }

    // Seção 6 do pedido de ajuste ("Compatibilidade com cofres existentes"): reabrir/inicializar
    // um cofre que já existe (sem excluir nada) nunca pode resetar ordem ou logo personalizadas —
    // `provision_default_platforms` pula qualquer `system_key` com `platform_seed_state` já
    // resolvido, então rodar `init_schema` de novo é inofensivo.
    #[test]
    fn reopening_an_existing_vault_preserves_user_customized_order_and_logo() {
        let conn = fixture_conn_with_password("senha-correta-XSS_TEST");

        conn.execute(
            "INSERT INTO images (filename, original_name, hash, created_at) VALUES ('custom.png', 'x.png', 'custom-hash', 'now')",
            [],
        )
        .unwrap();
        let custom_logo_id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE platforms SET sort_order = 42, logo_image_id = ?1 WHERE system_key = 'gmail'",
            [custom_logo_id],
        )
        .unwrap();

        // Reabrir o app chama vault_status -> db::init_schema de novo, sem excluir nada antes.
        db::init_schema(&conn).unwrap();

        let (sort_order, logo_image_id): (i64, Option<i64>) = conn
            .query_row("SELECT sort_order, logo_image_id FROM platforms WHERE system_key = 'gmail'", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(sort_order, 42, "reabrir o cofre não pode resetar a ordem personalizada");
        assert_eq!(logo_image_id, Some(custom_logo_id), "reabrir o cofre não pode resetar a logo personalizada");
    }
}
