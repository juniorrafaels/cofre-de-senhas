import { FormEvent, useState } from "react";
import { save as saveDialog, open as openDialog } from "@tauri-apps/plugin-dialog";
import { ArrowLeft, Database, FolderKanban, Layers, Lock, Monitor, Moon, Palette, Shield, Sun, Tag as TagIcon, Wand2 } from "lucide-react";
import { Button } from "../ui/Button";
import { Input, Label } from "../ui/Input";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useVaultStore } from "../../store/useVaultStore";
import { vaultCommands, backupCommands } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import { SecurityQuestionsSection } from "./SecurityQuestionsSection";
import { RecoveryKeySection } from "./RecoveryKeySection";
import { TagsManagerSection } from "./TagsManagerSection";
import { ListColumnsConfig } from "./ListColumnsConfig";
import { PasswordGeneratorSection } from "./PasswordGeneratorSection";
import { DeleteVaultSection } from "./DeleteVaultSection";
import { PlatformManagerModal } from "../platforms/PlatformManagerModal";
import { ProjectManagerModal } from "../projects/ProjectManagerModal";
import { PlatformIcon } from "../ui/PlatformIcon";
import { Avatar } from "../ui/Avatar";
import type { Platform, ProjectWithRelations, Tag } from "../../types";
import { SUPPORTED_LOCALES, type Locale } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";
import clsx from "clsx";

const AUTO_LOCK_OPTIONS = [1, 5, 15, 30, 60];

interface Props {
  platforms: Platform[];
  countsByPlatform: Record<number, number>;
  onPlatformsChanged: () => void;
  projects: ProjectWithRelations[];
  tags: Tag[];
}

type SettingsSection = "security" | "projects" | "platforms" | "appearance" | "tags" | "generator" | "data";

const LANGUAGE_LABEL_KEYS: Record<Locale, string> = {
  "pt-BR": "settings.appearance.languagePortuguese",
  en: "settings.appearance.languageEnglish",
  es: "settings.appearance.languageSpanish",
};

function SectionCard({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-[var(--color-text)]">
        {icon} {title}
      </div>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function Row({ label, description, children }: { label: string; description?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <p className="text-sm text-[var(--color-text)]">{label}</p>
        {description && <p className="text-xs text-[var(--color-text-muted)]">{description}</p>}
      </div>
      {children}
    </div>
  );
}

export function SettingsView({ platforms, countsByPlatform, onPlatformsChanged, projects, tags }: Props) {
  const settings = useSettingsStore();
  const lock = useVaultStore((s) => s.lock);
  const push = useToastStore((s) => s.push);
  const { t } = useTranslation();

  const SECTIONS: { key: SettingsSection; icon: React.ReactNode; title: string; description: string }[] = [
    { key: "security", icon: <Shield size={18} />, title: t("settings.sections.securityTitle"), description: t("settings.sections.securityDescription") },
    { key: "projects", icon: <FolderKanban size={18} />, title: t("settings.sections.projectsTitle"), description: t("settings.sections.projectsDescription") },
    { key: "platforms", icon: <Layers size={18} />, title: t("settings.sections.platformsTitle"), description: t("settings.sections.platformsDescription") },
    { key: "appearance", icon: <Palette size={18} />, title: t("settings.sections.appearanceTitle"), description: t("settings.sections.appearanceDescription") },
    { key: "tags", icon: <TagIcon size={18} />, title: t("settings.sections.tagsTitle"), description: t("settings.sections.tagsDescription") },
    { key: "generator", icon: <Wand2 size={18} />, title: t("settings.sections.generatorTitle"), description: t("settings.sections.generatorDescription") },
    { key: "data", icon: <Database size={18} />, title: t("settings.sections.dataTitle"), description: t("settings.sections.dataDescription") },
  ];

  const [activeSection, setActiveSection] = useState<SettingsSection | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);
  const [backupPassword, setBackupPassword] = useState("");
  // Restaurar substitui o cofre inteiro (inclusive a senha mestra) — o Rust exige a senha mestra
  // ATUAL e a verifica antes de abrir o arquivo de backup.
  const [restoreMasterPassword, setRestoreMasterPassword] = useState("");
  const [platformManagerOpen, setPlatformManagerOpen] = useState(false);
  const [projectManagerOpen, setProjectManagerOpen] = useState(false);

  async function handleChangePassword(e: FormEvent) {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      push(t("settings.security.mismatchError"), "error");
      return;
    }
    setChangingPassword(true);
    try {
      await vaultCommands.changeMasterPassword(currentPassword, newPassword);
      push(t("settings.security.changedSuccessToast"), "success");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      push(translateBackendError(t, err), "error");
    } finally {
      setChangingPassword(false);
    }
  }

  async function handleExportBackup() {
    if (backupPassword.length < 8) {
      push(t("settings.data.exportShortPasswordError"), "error");
      return;
    }
    const path = await saveDialog({
      title: t("settings.data.exportDialogTitle"),
      defaultPath: "cofre-backup.vaultbackup",
      filters: [{ name: t("settings.data.backupFileFilterName"), extensions: ["vaultbackup"] }],
    });
    if (!path) return;
    try {
      await backupCommands.export(path, backupPassword);
      push(t("settings.data.exportedSuccessToast"), "success");
    } catch (err) {
      push(translateBackendError(t, err), "error");
    }
  }

  async function handleImportBackup() {
    if (backupPassword.length < 8) {
      push(t("settings.data.importShortPasswordError"), "error");
      return;
    }
    if (!restoreMasterPassword) {
      push(t("settings.data.importMasterPasswordRequired"), "error");
      return;
    }
    const path = await openDialog({
      title: t("settings.data.importDialogTitle"),
      filters: [{ name: t("settings.data.backupFileFilterName"), extensions: ["vaultbackup"] }],
      multiple: false,
    });
    if (!path || Array.isArray(path)) return;
    try {
      await backupCommands.import(path, backupPassword, restoreMasterPassword);
      setRestoreMasterPassword("");
      push(t("settings.data.importedSuccessToast"), "success");
      await lock();
    } catch (err) {
      push(translateBackendError(t, err), "error");
    }
  }

  if (activeSection === null) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {SECTIONS.map((section) => (
            <button
              key={section.key}
              onClick={() => setActiveSection(section.key)}
              className="flex items-start gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 text-left transition-shadow hover:shadow-md hover:bg-[var(--color-surface-hover)]"
            >
              <div className="mt-0.5 text-[var(--color-accent)]">{section.icon}</div>
              <div>
                <p className="text-sm font-semibold text-[var(--color-text)]">{section.title}</p>
                <p className="text-xs text-[var(--color-text-muted)]">{section.description}</p>
              </div>
            </button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-5 p-6">
      <button
        onClick={() => setActiveSection(null)}
        className="flex items-center gap-1.5 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
      >
        <ArrowLeft size={15} /> {t("settings.backTitle")}
      </button>

      {activeSection === "security" && (
        <SectionCard icon={<Shield size={16} />} title={t("settings.security.title")}>
          <Row label={t("settings.security.lockNowLabel")} description={t("settings.security.lockNowDescription")}>
            <Button variant="secondary" onClick={() => lock()}>
              <Lock size={14} /> {t("settings.security.lockButton")}
            </Button>
          </Row>

          <Row label={t("settings.security.autoLockLabel")} description={t("settings.security.autoLockDescription")}>
            <select
              value={settings.autoLockMinutes}
              onChange={(e) => settings.setAutoLockMinutes(Number(e.target.value))}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-sm outline-none"
            >
              {AUTO_LOCK_OPTIONS.map((m) => (
                <option key={m} value={m}>
                  {m} {t("settings.security.minutesSuffix")}
                </option>
              ))}
            </select>
          </Row>

          <Row label={t("settings.security.lockOnMinimizeLabel")} description={t("settings.security.lockOnMinimizeDescription")}>
            <input
              type="checkbox"
              checked={settings.lockOnMinimize}
              onChange={(e) => settings.setLockOnMinimize(e.target.checked)}
              className="h-4 w-4"
            />
          </Row>

          <Row label={t("settings.security.clipboardClearLabel")} description={t("settings.security.clipboardClearDescription")}>
            <input
              type="checkbox"
              checked={settings.clipboardClearEnabled}
              onChange={(e) => settings.setClipboardClearEnabled(e.target.checked)}
              className="h-4 w-4"
            />
          </Row>

          {settings.clipboardClearEnabled && (
            <Row label={t("settings.security.clipboardTimeLabel")} description={t("settings.security.clipboardTimeDescription")}>
              <select
                value={settings.clipboardClearSeconds}
                onChange={(e) => settings.setClipboardClearSeconds(Number(e.target.value))}
                className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-sm outline-none"
              >
                {[10, 20, 30, 60].map((s) => (
                  <option key={s} value={s}>
                    {s}{t("settings.security.secondsSuffix")}
                  </option>
                ))}
              </select>
            </Row>
          )}

          <form onSubmit={handleChangePassword} className="space-y-2 border-t border-[var(--color-border)] pt-4">
            <p className="text-sm font-medium">{t("settings.security.changePasswordTitle")}</p>
            <div>
              <Label>{t("settings.security.currentPasswordLabel")}</Label>
              <Input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
            </div>
            <div>
              <Label>{t("settings.security.newPasswordLabel")}</Label>
              <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            </div>
            <div>
              <Label>{t("settings.security.confirmPasswordLabel")}</Label>
              <Input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
            </div>
            <Button type="submit" variant="primary" disabled={changingPassword || !currentPassword || !newPassword}>
              {changingPassword ? t("settings.security.changing") : t("settings.security.changeButton")}
            </Button>
          </form>

          <RecoveryKeySection />
          <SecurityQuestionsSection />
        </SectionCard>
      )}

      {activeSection === "platforms" && (
        <SectionCard icon={<Layers size={16} />} title={t("settings.sections.platformsTitle")}>
          <p className="text-xs text-[var(--color-text-muted)]">{t("platforms.section.description")}</p>
          <div className="flex flex-wrap gap-2">
            {platforms.slice(0, 8).map((p) => (
              <span key={p.id} className="flex items-center gap-1.5 rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs">
                <PlatformIcon icon={p.icon} size={13} /> {p.name}
              </span>
            ))}
            {platforms.length > 8 && (
              <span className="rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs text-[var(--color-text-muted)]">
                +{platforms.length - 8}
              </span>
            )}
          </div>
          <Button variant="secondary" onClick={() => setPlatformManagerOpen(true)}>
            {t("platforms.section.manageButton")}
          </Button>
        </SectionCard>
      )}

      {activeSection === "projects" && (
        <SectionCard icon={<FolderKanban size={16} />} title={t("settings.sections.projectsTitle")}>
          <p className="text-xs text-[var(--color-text-muted)]">{t("settings.projectsSection.description")}</p>
          <div className="flex flex-wrap gap-2">
            {projects.slice(0, 8).map((p) => (
              <span key={p.id} className="flex items-center gap-1.5 rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs">
                <Avatar imageId={p.avatar_image_id} size={16} /> {p.name}
              </span>
            ))}
            {projects.length > 8 && (
              <span className="rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs text-[var(--color-text-muted)]">
                +{projects.length - 8}
              </span>
            )}
          </div>
          <Button variant="secondary" onClick={() => setProjectManagerOpen(true)}>
            {t("settings.projectsSection.manageButton")}
          </Button>
        </SectionCard>
      )}

      {activeSection === "tags" && <TagsManagerSection onChanged={onPlatformsChanged} />}

      {activeSection === "appearance" && (
        <SectionCard icon={<Palette size={16} />} title={t("settings.appearance.title")}>
          <div className="flex gap-2">
            {(
              [
                { key: "light", label: t("settings.appearance.themeLight"), icon: <Sun size={14} /> },
                { key: "dark", label: t("settings.appearance.themeDark"), icon: <Moon size={14} /> },
                { key: "system", label: t("settings.appearance.themeSystem"), icon: <Monitor size={14} /> },
              ] as const
            ).map((opt) => (
              <button
                key={opt.key}
                onClick={() => settings.setTheme(opt.key)}
                className={clsx(
                  "flex flex-1 items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm",
                  settings.theme === opt.key
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]",
                )}
              >
                {opt.icon} {opt.label}
              </button>
            ))}
          </div>

          <div className="border-t border-[var(--color-border)] pt-4">
            <p className="mb-2 text-sm font-medium">{t("settings.appearance.languageLabel")}</p>
            <div className="flex gap-2">
              {SUPPORTED_LOCALES.map((locale) => (
                <button
                  key={locale}
                  onClick={() => settings.setLanguage(locale)}
                  className={clsx(
                    "flex-1 rounded-lg border px-3 py-2 text-sm",
                    settings.language === locale
                      ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                      : "border-[var(--color-border)] text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]",
                  )}
                >
                  {t(LANGUAGE_LABEL_KEYS[locale])}
                </button>
              ))}
            </div>
          </div>

          <div className="border-t border-[var(--color-border)] pt-4">
            <p className="mb-2 text-sm font-medium">{t("settings.appearance.listViewLabel")}</p>
            <ListColumnsConfig />
          </div>

          <p className="border-t border-[var(--color-border)] pt-4 text-xs text-[var(--color-text-muted)]">{t("settings.appearance.scaleHint")}</p>
        </SectionCard>
      )}

      {activeSection === "generator" && (
        <SectionCard icon={<Wand2 size={16} />} title={t("settings.sections.generatorTitle")}>
          <PasswordGeneratorSection />
        </SectionCard>
      )}

      {activeSection === "data" && (
        <SectionCard icon={<Database size={16} />} title={t("settings.data.title")}>
          <div>
            <Label>{t("settings.data.backupPasswordLabel")}</Label>
            <Input type="password" value={backupPassword} onChange={(e) => setBackupPassword(e.target.value)} placeholder={t("settings.data.backupPasswordPlaceholder")} />
          </div>
          <div>
            <Label>{t("settings.data.currentMasterPasswordLabel")}</Label>
            <Input
              type="password"
              value={restoreMasterPassword}
              onChange={(e) => setRestoreMasterPassword(e.target.value)}
              placeholder={t("settings.data.currentMasterPasswordPlaceholder")}
              autoComplete="current-password"
            />
          </div>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={handleExportBackup} className="flex-1">
              {t("settings.data.exportButton")}
            </Button>
            <Button variant="secondary" onClick={handleImportBackup} className="flex-1">
              {t("settings.data.importButton")}
            </Button>
          </div>
          <p className="text-xs text-[var(--color-text-muted)]">{t("settings.data.description")}</p>

          <DeleteVaultSection />
        </SectionCard>
      )}

      <PlatformManagerModal
        open={platformManagerOpen}
        onClose={() => setPlatformManagerOpen(false)}
        platforms={platforms}
        countsByPlatform={countsByPlatform}
        onChanged={onPlatformsChanged}
      />

      <ProjectManagerModal
        open={projectManagerOpen}
        onClose={() => setProjectManagerOpen(false)}
        projects={projects}
        tags={tags}
        onChanged={onPlatformsChanged}
      />
    </div>
  );
}
