mod commands;
mod crypto;
mod db;
mod migration;
mod native_lock;
mod state;
mod validate;

use state::VaultState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState::new())
        .setup(|app| {
            // Best-effort: nunca falha o startup do app (ver doc de `native_lock`).
            native_lock::install(&app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::vault_status,
            commands::vault::create_vault,
            commands::vault::unlock_vault,
            commands::vault::lock_vault,
            commands::vault::change_master_password,
            commands::vault::verify_master_password,
            commands::vault::delete_vault,
            commands::password_generator::generate_password,
            commands::clipboard::copy_to_clipboard,
            commands::backup::export_backup,
            commands::backup::import_backup,
            commands::images::import_image,
            commands::images::delete_image_file,
            commands::images::images_dir_path,
            commands::images::list_images,
            commands::images::update_image_name,
            commands::images::count_projects_using_image,
            commands::images::count_platforms_using_image,
            commands::images::count_accounts_using_image,
            commands::images::get_image_by_id,
            commands::images::find_image_by_hash,
            commands::images::create_image_record,
            commands::images::delete_image_record,
            commands::images::clear_avatar_for_image,
            commands::security_questions::security_questions_summary,
            commands::security_questions::add_security_question,
            commands::security_questions::update_security_question,
            commands::security_questions::delete_security_question,
            commands::security_questions::list_security_questions,
            commands::security_questions::get_recovery_questions,
            commands::security_questions::attempt_vault_recovery,
            commands::security_questions::reset_master_password_after_recovery,
            commands::recovery_key::recovery_key_status,
            commands::recovery_key::generate_recovery_key,
            commands::recovery_key::disable_recovery_key,
            commands::recovery_key::unlock_with_recovery_key,
            commands::platforms::list_platforms,
            commands::platforms::create_platform,
            commands::platforms::update_platform,
            commands::platforms::delete_platform,
            commands::platforms::reassign_accounts_platform,
            commands::platforms::reorder_platforms,
            commands::tags::list_tags,
            commands::tags::list_tags_with_usage,
            commands::tags::create_tag,
            commands::tags::rename_tag,
            commands::tags::delete_tag,
            commands::accounts::list_accounts_with_relations,
            commands::accounts::create_account,
            commands::accounts::update_account,
            commands::accounts::delete_account,
            commands::accounts::restore_account,
            commands::accounts::permanently_delete_account,
            commands::accounts::archive_account,
            commands::accounts::unarchive_account,
            commands::accounts::toggle_favorite,
            commands::accounts::reveal_account_password,
            commands::accounts::copy_account_password,
            commands::accounts::get_account_notes,
            commands::accounts::get_account_two_factor_details,
            commands::projects::list_projects_with_relations,
            commands::projects::create_project,
            commands::projects::update_project,
            commands::projects::delete_project,
            commands::projects::toggle_project_favorite,
            commands::projects::reorder_projects,
            commands::properties::list_property_definitions,
            commands::properties::ensure_property_definition,
            commands::properties::list_account_properties,
            commands::properties::create_account_property,
            commands::properties::update_account_property,
            commands::properties::delete_account_property,
            commands::properties::reveal_sensitive_property,
            commands::properties::copy_sensitive_property,
            commands::history::log_account_history,
            commands::history::list_account_history,
            commands::settings::get_all_settings,
            commands::settings::set_setting,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
