import { useState } from "react";
import { RotateCcw, Trash2 } from "lucide-react";
import type { AccountWithRelations } from "../../types";
import { Avatar } from "../ui/Avatar";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { useTranslation } from "../../i18n";

interface Props {
  accounts: AccountWithRelations[];
  onRestore: (account: AccountWithRelations) => void;
  onPermanentlyDelete: (account: AccountWithRelations) => void;
}

export function TrashView({ accounts, onRestore, onPermanentlyDelete }: Props) {
  const { t, intlLocale } = useTranslation();
  const [pending, setPending] = useState<AccountWithRelations | null>(null);

  if (accounts.length === 0) {
    return (
      <div className="p-6">
        <EmptyState title={t("accounts.trash.emptyTitle")} description={t("accounts.trash.emptyDescription")} />
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-muted)]">
              <th className="px-4 py-2.5 font-medium">{t("accounts.trash.accountHeader")}</th>
              <th className="px-4 py-2.5 font-medium">{t("accounts.trash.platformHeader")}</th>
              <th className="px-4 py-2.5 font-medium">{t("accounts.trash.deletedAtHeader")}</th>
              <th className="px-4 py-2.5 font-medium text-right">{t("accounts.trash.actionsHeader")}</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => (
              <tr key={account.id} className="border-b border-[var(--color-border)] last:border-0">
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2.5">
                    <Avatar imageId={account.avatar_image_id} platformIcon={account.platform?.icon ?? null} size={28} />
                    <span className="font-medium text-[var(--color-text)]">{account.name}</span>
                  </div>
                </td>
                <td className="px-4 py-2.5 text-[var(--color-text-muted)]">{account.platform?.name ?? t("common.dash")}</td>
                <td className="px-4 py-2.5 text-[var(--color-text-muted)]">
                  {account.deleted_at ? new Date(account.deleted_at).toLocaleString(intlLocale) : t("common.dash")}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center justify-end gap-1.5">
                    <Button variant="secondary" size="sm" onClick={() => onRestore(account)}>
                      <RotateCcw size={13} /> {t("accounts.trash.restore")}
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => setPending(account)}>
                      <Trash2 size={13} /> {t("accounts.trash.deletePermanently")}
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={!!pending}
        title={t("accounts.trash.confirmTitle")}
        message={t("accounts.trash.confirmMessage", { name: pending?.name ?? "" })}
        confirmLabel={t("accounts.trash.confirmLabel")}
        danger
        onConfirm={() => {
          if (pending) onPermanentlyDelete(pending);
          setPending(null);
        }}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
