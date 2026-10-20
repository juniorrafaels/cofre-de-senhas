import { FormEvent, useEffect, useState } from "react";
import { Eye, ImagePlus, X } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Input, Label, Textarea } from "../ui/Input";
import { Button } from "../ui/Button";
import { Avatar } from "../ui/Avatar";
import { AvatarPicker } from "./AvatarPicker";
import { PasswordField } from "./PasswordField";
import { PasswordStrengthMeter } from "../ui/PasswordStrengthMeter";
import { TagPicker } from "../ui/TagPicker";
import {
  ACCOUNT_STATUSES,
  TWO_FACTOR_METHODS,
  type AccountFormValues,
  type AccountStatus,
  type AccountWithRelations,
  type Platform,
  type Project,
  type Tag,
  type TwoFactorMethod,
} from "../../types";
import { accountSecretCommands } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import { tryFetch } from "../../lib/secretFields";
import { useTranslation } from "../../i18n";
import { accountStatusLabel, twoFactorMethodLabel } from "../../i18n/enumLabels";
import { translateBackendError } from "../../i18n/backendErrors";
import { isAllowedExternalUrl } from "../../lib/tauri";

interface Props {
  open: boolean;
  onClose: () => void;
  // `preserveFields`: campos sensíveis que falharam ao descriptografar e que o usuário não
  // editou — o chamador deve gravar de volta o ciphertext original em vez de recifrar uma
  // string vazia, para não destruir um dado que só não pôde ser exibido (nunca perder dados).
  onSubmit: (values: AccountFormValues, preserveFields: SensitiveField[]) => Promise<void>;
  platforms: Platform[];
  projects: Project[];
  tags: Tag[];
  editingAccount: AccountWithRelations | null;
  defaultPlatformId?: number | null;
  onRequestNewPlatform: () => void;
  newlyCreatedPlatformId?: number | null;
  onNewPlatformConsumed?: () => void;
  onRequestNewProject: () => void;
  newlyCreatedProjectId?: number | null;
  onNewProjectConsumed?: () => void;
}

// Falha de forma segura (Fase 2): um campo cifrado que não decifra NUNCA é tratado como texto
// puro legado — o backend já migra dados legados automaticamente a cada desbloqueio
// (`migrate_plaintext_secrets`), então uma falha aqui indica corrupção/adulteração, e é
// reportada como tal em vez de exibir/gravar de volta um valor não confiável.
export const SENSITIVE_FIELDS = ["notes", "two_factor_phone", "two_factor_email", "two_factor_app", "two_factor_notes"] as const;
export type SensitiveField = (typeof SENSITIVE_FIELDS)[number];

// Fase 4 (SECURITY_AUDIT_PHASE_4.md): busca notes/2FA já decifrados via commands específicos por
// `account_id` (`get_account_notes`/`get_account_two_factor_details`) — não existe mais um
// `decrypt_secret(ciphertext)` genérico para chamar aqui.
async function decryptSensitiveFields(accountId: number): Promise<{
  values: Record<SensitiveField, string>;
  failedFields: SensitiveField[];
}> {
  const [notesR, twoFactorR] = await Promise.all([
    tryFetch(() => accountSecretCommands.getNotes(accountId)),
    tryFetch(() => accountSecretCommands.getTwoFactorDetails(accountId)),
  ]);

  const values: Record<SensitiveField, string> = {
    notes: notesR.ok ? notesR.value : "",
    two_factor_phone: twoFactorR.ok ? twoFactorR.value.phone : "",
    two_factor_email: twoFactorR.ok ? twoFactorR.value.email : "",
    two_factor_app: twoFactorR.ok ? twoFactorR.value.app : "",
    two_factor_notes: twoFactorR.ok ? twoFactorR.value.notes : "",
  };
  const failedFields: SensitiveField[] = [];
  if (!notesR.ok) failedFields.push("notes");
  if (!twoFactorR.ok) {
    failedFields.push("two_factor_phone", "two_factor_email", "two_factor_app", "two_factor_notes");
  }
  return { values, failedFields };
}

/** `YYYY-MM-DD` do valor guardado (data pura, ou instante UTC convertido para a data local). */
export function toDateInputValue(stored: string | null | undefined): string {
  if (!stored) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(stored)) return stored;
  const ms = Date.parse(stored);
  if (Number.isNaN(ms)) return "";
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function todayInputValue(): string {
  return toDateInputValue(new Date().toISOString());
}

function emptyValues(defaultPlatformId?: number | null): AccountFormValues {
  return {
    name: "",
    platform_id: defaultPlatformId ?? null,
    category: "",
    username: "",
    email: "",
    password: "",
    login_url: "",
    website_url: "",
    notes: "",
    favorite: false,
    tags: [],
    avatar_image_id: null,
    projectIds: [],
    status: "active",
    two_factor_enabled: false,
    two_factor_method: null,
    two_factor_phone: "",
    two_factor_email: "",
    two_factor_app: "",
    two_factor_notes: "",
    last_login_at: "",
  };
}

export function AccountForm({
  open,
  onClose,
  onSubmit,
  platforms,
  projects,
  tags,
  editingAccount,
  defaultPlatformId,
  onRequestNewPlatform,
  newlyCreatedPlatformId,
  onNewPlatformConsumed,
  onRequestNewProject,
  newlyCreatedProjectId,
  onNewProjectConsumed,
}: Props) {
  const { t } = useTranslation();
  const [values, setValues] = useState<AccountFormValues>(emptyValues(defaultPlatformId));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [avatarPickerOpen, setAvatarPickerOpen] = useState(false);
  const [decryptErrors, setDecryptErrors] = useState<SensitiveField[]>([]);
  const push = useToastStore((s) => s.push);

  useEffect(() => {
    if (!open) return;
    if (editingAccount) {
      const accountId = editingAccount.id;
      setDecryptErrors([]);
      setValues({
        id: editingAccount.id,
        name: editingAccount.name,
        platform_id: editingAccount.platform_id,
        category: editingAccount.category ?? "",
        username: editingAccount.username ?? "",
        email: editingAccount.email ?? "",
        password: "",
        login_url: editingAccount.login_url ?? "",
        website_url: editingAccount.website_url ?? "",
        // Cifrados no banco — descriptografados de forma assíncrona logo abaixo.
        notes: "",
        favorite: !!editingAccount.favorite,
        tags: editingAccount.tags.map((t) => t.name),
        avatar_image_id: editingAccount.avatar_image_id,
        projectIds: editingAccount.projects.map((p) => p.id),
        status: editingAccount.status,
        two_factor_enabled: !!editingAccount.two_factor_enabled,
        two_factor_method: editingAccount.two_factor_method,
        two_factor_phone: "",
        two_factor_email: "",
        two_factor_app: "",
        two_factor_notes: "",
        // Só a parte de data (YYYY-MM-DD) cabe no <input type="date">; a data guardada pode ser
        // um instante UTC se veio de outra versão — nesse caso converte para a data local.
        last_login_at: toDateInputValue(editingAccount.last_login_at),
      });

      decryptSensitiveFields(editingAccount.id).then(({ values: decrypted, failedFields }) => {
        setValues((v) => (v.id === accountId ? { ...v, ...decrypted } : v));
        setDecryptErrors(failedFields);
      });
    } else {
      setDecryptErrors([]);
      setValues(emptyValues(defaultPlatformId));
    }
    setError(null);
  }, [open, editingAccount, defaultPlatformId]);

  useEffect(() => {
    if (open && newlyCreatedPlatformId) {
      handlePlatformChange(newlyCreatedPlatformId);
      onNewPlatformConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newlyCreatedPlatformId]);

  useEffect(() => {
    if (open && newlyCreatedProjectId) {
      setValues((v) => (v.projectIds.includes(newlyCreatedProjectId) ? v : { ...v, projectIds: [...v.projectIds, newlyCreatedProjectId] }));
      onNewProjectConsumed?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newlyCreatedProjectId]);

  function handlePlatformChange(platformId: number | null) {
    const platform = platforms.find((p) => p.id === platformId) ?? null;
    setValues((v) => ({
      ...v,
      platform_id: platformId,
      login_url: v.login_url || platform?.login_url || "",
      website_url: v.website_url || platform?.website_url || "",
      category: v.category || platform?.name || "",
    }));
  }

  async function handleRevealCurrentPassword() {
    if (!editingAccount?.has_password) return;
    try {
      const plaintext = await accountSecretCommands.revealPassword(editingAccount.id);
      setValues((v) => ({ ...v, password: plaintext }));
    } catch (err) {
      push(t("accounts.form.revealPasswordFailed", { error: translateBackendError(t, err) }), "error");
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (!values.name.trim()) {
      setError(t("accounts.form.nameRequiredError"));
      return;
    }
    setSaving(true);
    try {
      // Um campo que falhou ao descriptografar foi deixado em branco na UI; se o usuário não
      // digitou nada nele, preservamos o ciphertext original em vez de gravar "" por cima.
      const preserveFields = decryptErrors.filter((field) => !values[field].trim());
      await onSubmit(values, preserveFields);
      onClose();
    } catch (err) {
      setError(translateBackendError(t, err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={editingAccount ? t("accounts.form.titleEdit") : t("accounts.form.titleAdd")} width="lg">
      <form onSubmit={handleSubmit} className="space-y-4">
        {decryptErrors.length > 0 && (
          <p className="rounded-lg border border-[var(--color-danger)]/40 bg-[var(--color-danger)]/10 p-2.5 text-xs text-[var(--color-danger)]">
            {t("accounts.form.decryptWarning", { message: t("accounts.detail.decryptionFailed"), count: decryptErrors.length })}
          </p>
        )}
        <div className="flex items-center gap-3">
          <Avatar
            imageId={values.avatar_image_id}
            platformIcon={platforms.find((p) => p.id === values.platform_id)?.icon}
            platformLogoImageId={platforms.find((p) => p.id === values.platform_id)?.logo_image_id}
            size={56}
          />
          <Button type="button" variant="secondary" size="sm" onClick={() => setAvatarPickerOpen(true)}>
            <ImagePlus size={14} /> {t("accounts.form.changeImage")}
          </Button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>{t("accounts.form.nameLabel")}</Label>
            <Input value={values.name} onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))} autoFocus />
          </div>
          <div>
            <Label>{t("accounts.form.platformLabel")}</Label>
            <div className="flex gap-1.5">
              <select
                value={values.platform_id ?? ""}
                onChange={(e) => handlePlatformChange(e.target.value ? Number(e.target.value) : null)}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
              >
                <option value="">{t("common.selectPlaceholder")}</option>
                {platforms.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <Button type="button" variant="secondary" onClick={onRequestNewPlatform}>
                {t("accounts.form.newPlatform")}
              </Button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>{t("accounts.form.categoryLabel")}</Label>
            <Input value={values.category} onChange={(e) => setValues((v) => ({ ...v, category: e.target.value }))} />
          </div>
          <div>
            <Label>{t("accounts.form.usernameLabel")}</Label>
            <Input value={values.username} onChange={(e) => setValues((v) => ({ ...v, username: e.target.value }))} placeholder={t("accounts.form.usernamePlaceholder")} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>{t("accounts.form.emailLabel")}</Label>
            <Input type="email" value={values.email} onChange={(e) => setValues((v) => ({ ...v, email: e.target.value }))} />
          </div>
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <Label>{t("accounts.form.passwordLabel")}</Label>
              {editingAccount?.has_password && !values.password && (
                <button type="button" onClick={handleRevealCurrentPassword} className="flex items-center gap-1 text-xs text-[var(--color-accent)]">
                  <Eye size={12} /> {t("accounts.form.revealCurrent")}
                </button>
              )}
            </div>
            <PasswordField
              value={values.password}
              onChange={(v) => setValues((s) => ({ ...s, password: v }))}
              placeholder={editingAccount ? t("accounts.form.passwordPlaceholderEdit") : ""}
            />
            {/* Mesmo avaliador da senha mestra; só informa (não bloqueia o salvamento). */}
            <PasswordStrengthMeter password={values.password} />
          </div>
        </div>

        <div>
          <Label>{t("accounts.lastLogin.label")}</Label>
          <Input
            type="date"
            value={values.last_login_at}
            max={todayInputValue()}
            onChange={(e) => setValues((v) => ({ ...v, last_login_at: e.target.value }))}
          />
          <p className="mt-1 text-xs text-[var(--color-text-muted)]">{t("accounts.lastLogin.hint")}</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label>{t("accounts.form.loginUrlLabel")}</Label>
            <Input value={values.login_url} onChange={(e) => setValues((v) => ({ ...v, login_url: e.target.value }))} placeholder="https://..." />
            {values.login_url.trim() && !isAllowedExternalUrl(values.login_url.trim()) && (
              <p className="mt-1 text-xs text-[var(--color-danger)]">{t("errors.urlInvalidHint")}</p>
            )}
          </div>
          <div>
            <Label>{t("accounts.form.websiteUrlLabel")}</Label>
            <Input value={values.website_url} onChange={(e) => setValues((v) => ({ ...v, website_url: e.target.value }))} placeholder="https://..." />
            {values.website_url.trim() && !isAllowedExternalUrl(values.website_url.trim()) && (
              <p className="mt-1 text-xs text-[var(--color-danger)]">{t("errors.urlInvalidHint")}</p>
            )}
          </div>
        </div>

        <div>
          <Label>{t("accounts.form.notesLabel")}</Label>
          <Textarea rows={2} value={values.notes} onChange={(e) => setValues((v) => ({ ...v, notes: e.target.value }))} />
        </div>

        <div>
          <Label>{t("accounts.form.tagsLabel")}</Label>
          <TagPicker value={values.tags} onChange={(tags) => setValues((v) => ({ ...v, tags }))} suggestions={tags} />
        </div>

        <div>
          <Label>{t("accounts.form.projectsLabel")}</Label>
          <div className="flex flex-wrap gap-1.5">
            {values.projectIds.map((id) => {
              const project = projects.find((p) => p.id === id);
              if (!project) return null;
              return (
                <span key={id} className="flex items-center gap-1 rounded-full bg-[var(--color-accent)]/12 px-2.5 py-1 text-xs text-[var(--color-accent)]">
                  {project.name}
                  <button
                    type="button"
                    onClick={() => setValues((v) => ({ ...v, projectIds: v.projectIds.filter((pid) => pid !== id) }))}
                    className="hover:opacity-70"
                  >
                    <X size={11} />
                  </button>
                </span>
              );
            })}
          </div>
          <div className="mt-1.5 flex gap-1.5">
            <select
              value=""
              onChange={(e) => {
                const id = Number(e.target.value);
                if (id) setValues((v) => ({ ...v, projectIds: [...v.projectIds, id] }));
              }}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
            >
              <option value="">{t("accounts.form.addProjectPlaceholder")}</option>
              {projects
                .filter((p) => !values.projectIds.includes(p.id))
                .map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
            </select>
            <Button type="button" variant="secondary" onClick={onRequestNewProject}>
              {t("accounts.form.newProject")}
            </Button>
          </div>
        </div>

        <div>
          <Label>{t("accounts.form.statusLabel")}</Label>
          <select
            value={values.status}
            onChange={(e) => setValues((v) => ({ ...v, status: e.target.value as AccountStatus }))}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
          >
            {ACCOUNT_STATUSES.map((value) => (
              <option key={value} value={value}>
                {accountStatusLabel(t, value)}
              </option>
            ))}
          </select>
        </div>

        <div className="rounded-lg border border-[var(--color-border)] p-3">
          <label className="flex items-center gap-2 text-sm font-medium text-[var(--color-text)]">
            <input
              type="checkbox"
              checked={values.two_factor_enabled}
              onChange={(e) => setValues((v) => ({ ...v, two_factor_enabled: e.target.checked }))}
              className="h-4 w-4 rounded border-[var(--color-border)]"
            />
            {t("accounts.form.twoFactorEnabledLabel")}
          </label>

          {values.two_factor_enabled && (
            <div className="mt-3 space-y-3">
              <div>
                <Label>{t("accounts.form.methodLabel")}</Label>
                <select
                  value={values.two_factor_method ?? ""}
                  onChange={(e) => setValues((v) => ({ ...v, two_factor_method: (e.target.value || null) as TwoFactorMethod | null }))}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
                >
                  <option value="">{t("common.selectPlaceholder")}</option>
                  {TWO_FACTOR_METHODS.map((value) => (
                    <option key={value} value={value}>
                      {twoFactorMethodLabel(t, value)}
                    </option>
                  ))}
                </select>
              </div>

              {(values.two_factor_method === "sms" || values.two_factor_method === "whatsapp") && (
                <div>
                  <Label>{t("accounts.form.phoneUsedLabel")}</Label>
                  <Input
                    value={values.two_factor_phone}
                    onChange={(e) => setValues((v) => ({ ...v, two_factor_phone: e.target.value }))}
                    placeholder={t("accounts.form.phonePlaceholder")}
                  />
                </div>
              )}

              {values.two_factor_method === "email" && (
                <div>
                  <Label>{t("accounts.form.emailUsedLabel")}</Label>
                  <Input
                    value={values.two_factor_email}
                    onChange={(e) => setValues((v) => ({ ...v, two_factor_email: e.target.value }))}
                    placeholder={values.email || t("accounts.form.emailUsedPlaceholder")}
                  />
                </div>
              )}

              {values.two_factor_method === "authenticator" && (
                <div>
                  <Label>{t("accounts.form.appLabel")}</Label>
                  <Input
                    value={values.two_factor_app}
                    onChange={(e) => setValues((v) => ({ ...v, two_factor_app: e.target.value }))}
                    placeholder={t("accounts.form.appPlaceholder")}
                    list="authenticator-apps"
                  />
                  <datalist id="authenticator-apps">
                    <option value="Google Authenticator" />
                    <option value="Microsoft Authenticator" />
                    <option value="Authy" />
                    <option value="1Password" />
                    <option value="Bitwarden" />
                  </datalist>
                </div>
              )}

              <div>
                <Label>{t("accounts.form.notesLabel")}</Label>
                <Input
                  value={values.two_factor_notes}
                  onChange={(e) => setValues((v) => ({ ...v, two_factor_notes: e.target.value }))}
                  placeholder={t("accounts.form.notesOptionalPlaceholder")}
                />
              </div>
            </div>
          )}
        </div>

        <label className="flex items-center gap-2 text-sm text-[var(--color-text)]">
          <input
            type="checkbox"
            checked={values.favorite}
            onChange={(e) => setValues((v) => ({ ...v, favorite: e.target.checked }))}
            className="h-4 w-4 rounded border-[var(--color-border)]"
          />
          {t("accounts.form.favoriteLabel")}
        </label>

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] pt-4">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={saving}>
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </form>

      <AvatarPicker
        open={avatarPickerOpen}
        onClose={() => setAvatarPickerOpen(false)}
        currentImageId={values.avatar_image_id}
        onSelect={(imageId) => setValues((v) => ({ ...v, avatar_image_id: imageId }))}
      />
    </Modal>
  );
}
