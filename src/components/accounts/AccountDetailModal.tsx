import { useEffect, useState } from "react";
import { Archive, ArchiveRestore, CheckCircle2, Copy, ExternalLink, Eye, EyeOff, Pencil, ShieldAlert, Trash2 } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { Avatar } from "../ui/Avatar";
import { AccountPropertiesSection } from "./AccountPropertiesSection";
import { AccountHistorySection } from "./AccountHistorySection";
import { type AccountWithRelations } from "../../types";
import { accountSecretCommands, openLoginUrl } from "../../lib/tauri";
import { useCopy, useCopySecret } from "../../lib/useCopy";
import { useToastStore } from "../../store/useToastStore";
import { tryFetch } from "../../lib/secretFields";
import { useTranslation } from "../../i18n";
import { accountStatusLabel, twoFactorMethodLabel } from "../../i18n/enumLabels";
import { UpdatedBadge } from "./UpdatedBadge";
import { formatLastLogin, getUpdateBadge } from "../../lib/accountBadge";
import { translateBackendError } from "../../i18n/backendErrors";

interface Props {
  account: AccountWithRelations | null;
  onClose: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onArchiveToggle: () => void;
  /**
   * Confirmação MANUAL de "conta atualizada" (único caminho que renova o selo de 90 dias).
   * Devolve o instante UTC gravado.
   */
  onMarkUpdated: (account: AccountWithRelations) => Promise<string>;
}

const STATUS_COLORS: Record<string, string> = {
  active: "bg-[var(--color-success)]",
  blocked: "bg-[var(--color-danger)]",
  recovering: "bg-amber-500",
  suspended: "bg-amber-500",
  disabled: "bg-[var(--color-text-muted)]",
  archived: "bg-[var(--color-text-muted)]",
};

// `twoFactorEmail` já vem decifrado do estado do componente (Fase 4: não existe mais
// `account.two_factor_email` em texto cifrado neste tipo — ver `accountSecretCommands.getTwoFactorDetails`).
function computeHealth(t: (key: string) => string, account: AccountWithRelations, twoFactorEmail: string) {
  const checks = [
    { ok: !!account.avatar_image_id, label: t("accounts.detail.checkPhoto") },
    { ok: account.projects.length > 0, label: t("accounts.detail.checkProject") },
    { ok: !!account.two_factor_enabled, label: t("accounts.detail.checkTwoFactor") },
    { ok: !!(twoFactorEmail || account.email), label: t("accounts.detail.checkContactEmail") },
    { ok: account.status === "active", label: t("accounts.detail.checkActiveStatus") },
  ];
  const okCount = checks.filter((c) => c.ok).length;
  return { checks, okCount, total: checks.length };
}

const EMPTY_TWO_FACTOR = { phone: "", email: "", app: "", notes: "" };

export function AccountDetailModal({ account, onClose, onEdit, onDelete, onArchiveToggle, onMarkUpdated }: Props) {
  const { t, intlLocale } = useTranslation();
  // Confirmação recém-gravada: vale até a lista ser recarregada e trazer o mesmo valor.
  const [confirmedOverride, setConfirmedOverride] = useState<{ id: number; value: string } | null>(null);
  const [marking, setMarking] = useState(false);
  const [tab, setTab] = useState<"details" | "properties" | "history">("details");
  const [twoFactor, setTwoFactor] = useState(EMPTY_TWO_FACTOR);
  const [notes, setNotes] = useState("");
  // Campos que falharam ao descriptografar (Fase 2: nunca exibimos o ciphertext bruto nem
  // assumimos que é texto puro legado — a migração automática no unlock já cuidou disso).
  const [decryptErrors, setDecryptErrors] = useState<Set<string>>(new Set());
  const copy = useCopy();
  const copySecret = useCopySecret();
  const push = useToastStore((s) => s.push);

  useEffect(() => {
    setTab("details");
    setTwoFactor(EMPTY_TWO_FACTOR);
    setNotes("");
    setDecryptErrors(new Set());
    if (!account) return;
    let cancelled = false;
    Promise.all([
      tryFetch(() => accountSecretCommands.getTwoFactorDetails(account.id)),
      tryFetch(() => accountSecretCommands.getNotes(account.id)),
    ]).then(([twoFactorR, notesR]) => {
      if (cancelled) return;
      setTwoFactor({
        phone: twoFactorR.ok ? twoFactorR.value.phone : "",
        email: twoFactorR.ok ? twoFactorR.value.email : "",
        app: twoFactorR.ok ? twoFactorR.value.app : "",
        notes: twoFactorR.ok ? twoFactorR.value.notes : "",
      });
      setNotes(notesR.ok ? notesR.value : "");
      const failed = new Set<string>();
      if (!twoFactorR.ok) {
        failed.add("phone");
        failed.add("email");
        failed.add("app");
        failed.add("two_factor_notes");
      }
      if (!notesR.ok) failed.add("notes");
      setDecryptErrors(failed);
    });
    return () => {
      cancelled = true;
    };
  }, [account?.id]);

  if (!account) return null;

  const loginUrl = account.login_url || account.platform?.login_url || "";
  const health = computeHealth(t, account, twoFactor.email);

  // Sem cache: cada reveal/cópia decifra de novo em vez de guardar o plaintext em estado do
  // React entre chamadas — decifrar com a DEK já em memória é barato, e isso reduz o tempo em
  // que a senha decifrada fica pendurada em algum lugar do frontend.
  async function ensurePassword(): Promise<string> {
    if (!account?.has_password) return "";
    return accountSecretCommands.revealPassword(account.id);
  }

  async function handleLogin() {
    if (!loginUrl) {
      push(t("accounts.toasts.noLoginUrl"), "error");
      return;
    }
    await openLoginUrl(loginUrl);
  }

  async function handleCopyPassword() {
    // Decifra e copia inteiramente no backend (não usa `ensurePassword`/`password` — este botão
    // só copia, não precisa que o plaintext passe pelo estado do React).
    if (!account) return;
    await copySecret(account.has_password, (seconds) => accountSecretCommands.copyPassword(account.id, seconds), t("accounts.passwordField.label"));
  }

  const decryptionFailedMessage = t("accounts.detail.decryptionFailed");

  const confirmedAt = confirmedOverride?.id === account.id ? confirmedOverride.value : account.update_confirmed_at;
  const badgeState = getUpdateBadge(confirmedAt);

  async function handleMarkUpdated() {
    if (!account || marking) return;
    setMarking(true);
    try {
      const stamp = await onMarkUpdated(account);
      setConfirmedOverride({ id: account.id, value: stamp });
      push(t("accounts.updateBadge.markedToast"), "success");
    } catch (err) {
      push(t("accounts.updateBadge.markFailedToast", { error: translateBackendError(t, err) }), "error");
    } finally {
      setMarking(false);
    }
  }

  return (
    <Modal open={!!account} onClose={onClose} title={account.platform?.name ?? t("accounts.detail.fallbackTitle")} width="md">
      <div className="mb-4 flex items-center gap-3">
        <Avatar
          imageId={account.avatar_image_id}
          platformIcon={account.platform?.icon ?? null}
          platformLogoImageId={account.platform?.logo_image_id}
          size={44}
        />
        <div className="min-w-0 flex-1">
          <p className="text-base font-semibold">{account.name}</p>
          <p className="text-sm text-[var(--color-text-muted)]">{account.category || account.platform?.name}</p>
        </div>
        <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs text-[var(--color-text)]">
          <span className={`h-1.5 w-1.5 rounded-full ${STATUS_COLORS[account.status] ?? "bg-[var(--color-text-muted)]"}`} />
          {accountStatusLabel(t, account.status)}
        </span>
      </div>

      <div className="mb-4 flex gap-1 border-b border-[var(--color-border)]">
        {(
          [
            { key: "details", label: t("accounts.detail.tabDetails") },
            { key: "properties", label: t("accounts.detail.tabProperties") },
            { key: "history", label: t("accounts.detail.tabHistory") },
          ] as const
        ).map((tabItem) => (
          <button
            key={tabItem.key}
            onClick={() => setTab(tabItem.key)}
            className={`px-3 py-2 text-sm ${tab === tabItem.key ? "border-b-2 border-[var(--color-accent)] text-[var(--color-accent)] font-medium" : "text-[var(--color-text-muted)]"}`}
          >
            {tabItem.label}
          </button>
        ))}
      </div>

      {tab === "details" && (
        <div className="space-y-3">
          <Field label={t("accounts.detail.usernameLabel")} value={account.username || t("common.dash")} onCopy={() => copy(account.username, t("accounts.form.usernameLabel"))} />
          <Field label={t("accounts.detail.emailLabel")} value={account.email || t("common.dash")} onCopy={() => copy(account.email, t("accounts.detail.emailLabel"))} />

          <div>
            <p className="mb-1.5 text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.detail.passwordLabel")}</p>
            <div className="flex items-center gap-1.5">
              <div className="flex-1">
                <PasswordFieldLazy account={account} onReveal={ensurePassword} />
              </div>
              <button onClick={handleCopyPassword} className="rounded-md p-2 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]" title={t("accounts.detail.copyPassword")}>
                <Copy size={15} />
              </button>
            </div>
          </div>

          {loginUrl && <Field label={t("accounts.detail.loginUrlLabel")} value={loginUrl} mono />}

          {/* Último login: dado informado pelo usuário; distinto de cadastro, edição e confirmação. */}
          <Field label={t("accounts.lastLogin.label")} value={formatLastLogin(account.last_login_at, intlLocale) || t("accounts.lastLogin.none")} />

          <div className="space-y-1.5 rounded-lg border border-[var(--color-border)] p-2.5" data-testid="update-confirmation">
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.updateBadge.lastConfirmedLabel")}</p>
              <UpdatedBadge confirmedAt={confirmedAt} />
            </div>
            <p className="text-sm text-[var(--color-text)]" data-testid="update-confirmation-status">
              {badgeState.status === "valid"
                ? t("accounts.updateBadge.expiresOn", { date: badgeState.expiresAt.toLocaleDateString(intlLocale), days: badgeState.daysLeft })
                : badgeState.status === "expired"
                  ? t("accounts.updateBadge.expiredTooltip", {
                      date: badgeState.confirmedAt.toLocaleDateString(intlLocale),
                      expires: badgeState.expiredAt.toLocaleDateString(intlLocale),
                    })
                  : t("accounts.updateBadge.neverConfirmed")}
            </p>
            <Button type="button" variant="secondary" size="sm" onClick={handleMarkUpdated} disabled={marking}>
              <CheckCircle2 size={14} /> {t("accounts.updateBadge.markButton")}
            </Button>
            <p className="text-xs text-[var(--color-text-muted)]">{t("accounts.updateBadge.markHint")}</p>
          </div>

          {!!account.two_factor_enabled && (
            <div className="rounded-lg border border-[var(--color-border)] p-2.5">
              <p className="mb-1 text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.detail.twoFactorLabel")}</p>
              <p className="text-sm text-[var(--color-text)]">{account.two_factor_method ? twoFactorMethodLabel(t, account.two_factor_method) : t("common.dash")}</p>
              {twoFactor.phone && <p className="text-xs text-[var(--color-text-muted)]">{t("accounts.detail.phoneLine", { value: twoFactor.phone })}</p>}
              {twoFactor.email && <p className="text-xs text-[var(--color-text-muted)]">{t("accounts.detail.emailLine", { value: twoFactor.email })}</p>}
              {twoFactor.app && <p className="text-xs text-[var(--color-text-muted)]">{t("accounts.detail.appLine", { value: twoFactor.app })}</p>}
              {twoFactor.notes && <p className="text-xs text-[var(--color-text-muted)]">{twoFactor.notes}</p>}
              {(decryptErrors.has("phone") || decryptErrors.has("email") || decryptErrors.has("app") || decryptErrors.has("two_factor_notes")) && (
                <p className="text-xs text-[var(--color-danger)]">{decryptionFailedMessage}</p>
              )}
            </div>
          )}

          {(notes || decryptErrors.has("notes")) && (
            <div>
              <p className="mb-1 text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.detail.notesLabel")}</p>
              {decryptErrors.has("notes") ? (
                <p className="text-sm text-[var(--color-danger)]">{decryptionFailedMessage}</p>
              ) : (
                <p className="text-sm text-[var(--color-text)]">{notes}</p>
              )}
            </div>
          )}

          {account.tags.length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.detail.tagsLabel")}</p>
              <div className="flex flex-wrap gap-1.5">
                {account.tags.map((tag) => (
                  <span key={tag.id} className="rounded-full bg-[var(--color-surface-hover)] px-2.5 py-1 text-xs text-[var(--color-text-muted)]">
                    {tag.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-lg border border-[var(--color-border)] p-2.5">
            <div className="mb-1.5 flex items-center justify-between">
              <p className="text-xs font-medium text-[var(--color-text-muted)]">{t("accounts.detail.healthTitle")}</p>
              <span className="text-xs text-[var(--color-text-muted)]">{t("accounts.detail.healthOf", { ok: health.okCount, total: health.total })}</span>
            </div>
            <div className="space-y-1">
              {health.checks.map((c) => (
                <div key={c.label} className="flex items-center gap-1.5 text-xs">
                  {c.ok ? (
                    <CheckCircle2 size={13} className="text-[var(--color-success)]" />
                  ) : (
                    <ShieldAlert size={13} className="text-amber-500" />
                  )}
                  <span className={c.ok ? "text-[var(--color-text-muted)]" : "text-[var(--color-text)]"}>{c.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "properties" && <AccountPropertiesSection accountId={account.id} />}
      {tab === "history" && <AccountHistorySection accountId={account.id} />}

      <div className="mt-6 flex flex-wrap gap-2 border-t border-[var(--color-border)] pt-4">
        <Button variant="primary" onClick={handleLogin}>
          <ExternalLink size={15} /> {t("accounts.detail.openLogin")}
        </Button>
        <Button variant="secondary" onClick={onEdit}>
          <Pencil size={15} /> {t("accounts.detail.edit")}
        </Button>
        <Button variant="secondary" onClick={onArchiveToggle}>
          {account.status === "archived" ? (
            <>
              <ArchiveRestore size={15} /> {t("accounts.detail.unarchive")}
            </>
          ) : (
            <>
              <Archive size={15} /> {t("accounts.detail.archive")}
            </>
          )}
        </Button>
        <Button variant="danger" className="ml-auto" onClick={onDelete}>
          <Trash2 size={15} /> {t("accounts.detail.delete")}
        </Button>
      </div>
    </Modal>
  );
}

function Field({ label, value, onCopy, mono }: { label: string; value: string; onCopy?: () => void; mono?: boolean }) {
  return (
    <div>
      <p className="mb-1 text-xs font-medium text-[var(--color-text-muted)]">{label}</p>
      <div className="flex items-center gap-1.5">
        <p className={`flex-1 truncate text-sm text-[var(--color-text)] ${mono ? "font-mono text-xs" : ""}`}>{value}</p>
        {onCopy && (
          <button onClick={onCopy} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
            <Copy size={14} />
          </button>
        )}
      </div>
    </div>
  );
}

function PasswordFieldLazy({
  account,
  onReveal,
}: {
  account: AccountWithRelations;
  onReveal: () => Promise<string>;
}) {
  const { t } = useTranslation();
  const [revealed, setRevealed] = useState(false);
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setValue("");
    setRevealed(false);
  }, [account.id]);

  if (!account.has_password) {
    return <p className="text-sm text-[var(--color-text-muted)]">{t("accounts.detail.noPassword")}</p>;
  }

  async function toggleReveal() {
    if (revealed) {
      // Ao esconder de novo, o valor decifrado é removido do estado do React (não fica
      // pendurado em memória só porque a UI não o exibe mais) — precisa decifrar de novo
      // para revelar uma próxima vez, o que é barato (a DEK já está em memória no Rust).
      setRevealed(false);
      setValue("");
      return;
    }
    setLoading(true);
    try {
      const plaintext = await onReveal();
      setValue(plaintext);
      setRevealed(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative">
      <Input type={revealed ? "text" : "password"} value={revealed ? value : "••••••••••"} readOnly />
      <button
        type="button"
        onClick={toggleReveal}
        disabled={loading}
        className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
        title={revealed ? t("accounts.detail.hidePassword") : t("accounts.detail.showPassword")}
      >
        {revealed ? <EyeOff size={15} /> : <Eye size={15} />}
      </button>
    </div>
  );
}
