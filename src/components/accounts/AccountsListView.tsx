import { Copy, ExternalLink, Key, Pencil, Star } from "lucide-react";
import { type AccountWithRelations, type ListColumnKey } from "../../types";
import { Avatar } from "../ui/Avatar";
import { StatusBadge } from "../ui/StatusBadge";
import { UpdatedBadge } from "./UpdatedBadge";
import { formatLastLogin } from "../../lib/accountBadge";
import { useCopy, useCopySecret } from "../../lib/useCopy";
import { accountSecretCommands, openLoginUrl } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";
import { listColumnLabel } from "../../i18n/enumLabels";

interface Props {
  accounts: AccountWithRelations[];
  columns: ListColumnKey[];
  onOpenDetail: (account: AccountWithRelations) => void;
  onEdit: (account: AccountWithRelations) => void;
  onToggleFavorite: (account: AccountWithRelations) => void;
}

function ColumnCell({
  column,
  account,
  t,
  intlLocale,
}: {
  column: ListColumnKey;
  account: AccountWithRelations;
  t: (key: string) => string;
  intlLocale: string;
}) {
  switch (column) {
    case "avatar":
      return (
        <Avatar
          imageId={account.avatar_image_id}
          platformIcon={account.platform?.icon ?? null}
          platformLogoImageId={account.platform?.logo_image_id}
          size={28}
        />
      );
    case "name":
      return (
        <div className="flex items-center gap-1.5">
          <span className="font-medium text-[var(--color-text)]">{account.name}</span>
          {!!account.favorite && <Star size={12} fill="currentColor" className="text-amber-400" />}
          <UpdatedBadge confirmedAt={account.update_confirmed_at} />
        </div>
      );
    case "platform":
      return <span className="text-[var(--color-text-muted)]">{account.platform?.name ?? t("common.dash")}</span>;
    case "username":
      return <span className="text-[var(--color-text-muted)]">{account.username || t("common.dash")}</span>;
    case "email":
      return <span className="text-[var(--color-text-muted)]">{account.email || t("common.dash")}</span>;
    case "project":
      return <span className="text-[var(--color-text-muted)]">{account.projects.map((p) => p.name).join(", ") || t("common.dash")}</span>;
    case "status":
      return <StatusBadge status={account.status} />;
    case "tags":
      return <span className="text-[var(--color-text-muted)]">{account.tags.map((t2) => t2.name).join(", ") || t("common.dash")}</span>;
    case "updated_at":
      return <span className="text-[var(--color-text-muted)]">{new Date(account.updated_at).toLocaleDateString(intlLocale)}</span>;
    case "last_login":
      return <span className="text-[var(--color-text-muted)]">{formatLastLogin(account.last_login_at, intlLocale) || t("common.dash")}</span>;
    case "two_factor":
      return <span className="text-[var(--color-text-muted)]">{account.two_factor_enabled ? t("accounts.list.yes") : t("accounts.list.no")}</span>;
    default:
      return null;
  }
}

export function AccountsListView({ accounts, columns, onOpenDetail, onEdit, onToggleFavorite }: Props) {
  const { t, intlLocale } = useTranslation();
  const copy = useCopy();
  const copySecret = useCopySecret();
  const push = useToastStore((s) => s.push);
  const activeColumns = columns.length > 0 ? columns : (["avatar", "name"] as ListColumnKey[]);

  async function handleLogin(e: React.MouseEvent, account: AccountWithRelations) {
    e.stopPropagation();
    const url = account.login_url || account.platform?.login_url || "";
    if (!url) {
      push(t("accounts.toasts.noLoginUrl"), "error");
      return;
    }
    await openLoginUrl(url);
  }

  async function handleCopyPassword(e: React.MouseEvent, account: AccountWithRelations) {
    e.stopPropagation();
    // Decifra e copia inteiramente no backend — o plaintext da senha nunca passa pelo frontend.
    await copySecret(account.has_password, (seconds) => accountSecretCommands.copyPassword(account.id, seconds), t("accounts.passwordField.label"));
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-muted)]">
            {activeColumns.map((col) => (
              <th key={col} className="px-4 py-2.5 font-medium">
                {col === "avatar" ? "" : listColumnLabel(t, col)}
              </th>
            ))}
            <th className="px-4 py-2.5 font-medium text-right">{t("accounts.list.actionsHeader")}</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((account) => (
            <tr
              key={account.id}
              onClick={() => onOpenDetail(account)}
              className="cursor-pointer border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface-hover)]"
            >
              {activeColumns.map((col) => (
                <td key={col} className="px-4 py-2.5">
                  <ColumnCell column={col} account={account} t={t} intlLocale={intlLocale} />
                </td>
              ))}
              <td className="px-4 py-2.5">
                <div className="flex items-center justify-end gap-0.5">
                  <button onClick={(e) => handleLogin(e, account)} title={t("accounts.list.openLogin")} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]">
                    <ExternalLink size={14} />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      copy(account.username || account.email, t("accounts.form.usernameLabel"));
                    }}
                    title={t("accounts.list.copyUsername")}
                    className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <Copy size={14} />
                  </button>
                  <button onClick={(e) => handleCopyPassword(e, account)} title={t("accounts.list.copyPassword")} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]">
                    <Key size={14} />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleFavorite(account);
                    }}
                    title={t("accounts.list.favorite")}
                    className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-amber-400"
                  >
                    <Star size={14} fill={account.favorite ? "currentColor" : "none"} className={account.favorite ? "text-amber-400" : ""} />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onEdit(account);
                    }}
                    title={t("accounts.list.edit")}
                    className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <Pencil size={14} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
