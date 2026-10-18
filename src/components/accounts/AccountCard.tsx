import { Copy, ExternalLink, Key, Pencil, Star } from "lucide-react";
import type { AccountWithRelations } from "../../types";
import { Avatar } from "../ui/Avatar";
import { StatusBadge } from "../ui/StatusBadge";
import { useCopy, useCopySecret } from "../../lib/useCopy";
import { accountSecretCommands, openLoginUrl } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

interface Props {
  account: AccountWithRelations;
  onOpenDetail: () => void;
  onEdit: () => void;
  onToggleFavorite: () => void;
}

export function AccountCard({ account, onOpenDetail, onEdit, onToggleFavorite }: Props) {
  const { t } = useTranslation();
  const copy = useCopy();
  const copySecret = useCopySecret();
  const push = useToastStore((s) => s.push);

  const loginUrl = account.login_url || account.platform?.login_url || "";

  async function handleLogin(e: React.MouseEvent) {
    e.stopPropagation();
    if (!loginUrl) {
      push(t("accounts.toasts.noLoginUrl"), "error");
      return;
    }
    try {
      await openLoginUrl(loginUrl);
    } catch (err) {
      push(t("accounts.toasts.openBrowserFailed", { error: translateBackendError(t, err) }), "error");
    }
  }

  async function handleCopyPassword(e: React.MouseEvent) {
    e.stopPropagation();
    // Decifra e copia inteiramente no backend — o plaintext da senha nunca passa pelo frontend
    // aqui, já que a intenção deste botão é só copiar (o "revelar" fica no modal de detalhes).
    await copySecret(account.has_password, (seconds) => accountSecretCommands.copyPassword(account.id, seconds), t("accounts.passwordField.label"));
  }

  return (
    <div
      onClick={onOpenDetail}
      className="group cursor-pointer rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 transition-shadow hover:shadow-md"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2.5">
          <Avatar
            imageId={account.avatar_image_id}
            platformIcon={account.platform?.icon ?? null}
            platformLogoImageId={account.platform?.logo_image_id}
            size={36}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <p className="truncate text-sm font-semibold text-[var(--color-text)]">{account.name}</p>
              <StatusBadge status={account.status} />
            </div>
            <p className="truncate text-xs text-[var(--color-text-muted)]">{account.username || account.email || t("common.dash")}</p>
          </div>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggleFavorite();
          }}
          className="shrink-0 text-[var(--color-text-muted)] hover:text-amber-400"
        >
          <Star size={16} fill={account.favorite ? "currentColor" : "none"} className={account.favorite ? "text-amber-400" : ""} />
        </button>
      </div>

      {account.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {account.tags.slice(0, 3).map((tag) => (
            <span key={tag.id} className="rounded-full bg-[var(--color-surface-hover)] px-2 py-0.5 text-[11px] text-[var(--color-text-muted)]">
              {tag.name}
            </span>
          ))}
        </div>
      )}

      <div className="mt-4 flex items-center gap-1 border-t border-[var(--color-border)] pt-3 opacity-0 transition-opacity group-hover:opacity-100">
        <button onClick={handleLogin} title={t("accounts.card.openLogin")} className="flex flex-1 items-center justify-center rounded-md py-1.5 text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]">
          <ExternalLink size={14} />
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            copy(account.username || account.email, t("accounts.form.usernameLabel"));
          }}
          title={t("accounts.card.copyUsername")}
          className="flex flex-1 items-center justify-center rounded-md py-1.5 text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
        >
          <Copy size={14} />
        </button>
        <button onClick={handleCopyPassword} title={t("accounts.card.copyPassword")} className="flex flex-1 items-center justify-center rounded-md py-1.5 text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]">
          <Key size={14} />
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onEdit();
          }}
          title={t("accounts.card.edit")}
          className="flex flex-1 items-center justify-center rounded-md py-1.5 text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
        >
          <Pencil size={14} />
        </button>
      </div>
    </div>
  );
}
