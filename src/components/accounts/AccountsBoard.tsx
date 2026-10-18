import { Plus } from "lucide-react";
import type { AccountWithRelations, ViewMode } from "../../types";
import { AccountCard } from "./AccountCard";
import { AccountsListView } from "./AccountsListView";
import { EmptyState } from "../ui/EmptyState";
import { Button } from "../ui/Button";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useTranslation } from "../../i18n";

interface Props {
  accounts: AccountWithRelations[];
  viewMode: ViewMode;
  onOpenDetail: (account: AccountWithRelations) => void;
  onEdit: (account: AccountWithRelations) => void;
  onToggleFavorite: (account: AccountWithRelations) => void;
  emptyTitle: string;
  emptyDescription: string;
  onAddAccount: () => void;
}

export function AccountsBoard({
  accounts,
  viewMode,
  onOpenDetail,
  onEdit,
  onToggleFavorite,
  emptyTitle,
  emptyDescription,
  onAddAccount,
}: Props) {
  const listColumns = useSettingsStore((s) => s.listColumns);
  const listScale = useSettingsStore((s) => s.listScale);
  const { t } = useTranslation();

  if (accounts.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        description={emptyDescription}
        action={
          <Button variant="primary" onClick={onAddAccount}>
            <Plus size={15} /> {t("layout.topbar.addAccount")}
          </Button>
        }
      />
    );
  }

  if (viewMode === "list") {
    return (
      <div style={{ zoom: listScale / 100 }}>
        <AccountsListView accounts={accounts} columns={listColumns} onOpenDetail={onOpenDetail} onEdit={onEdit} onToggleFavorite={onToggleFavorite} />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4" style={{ zoom: listScale / 100 }}>
      {accounts.map((account) => (
        <AccountCard
          key={account.id}
          account={account}
          onOpenDetail={() => onOpenDetail(account)}
          onEdit={() => onEdit(account)}
          onToggleFavorite={() => onToggleFavorite(account)}
        />
      ))}
    </div>
  );
}
