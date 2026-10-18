import { useMemo, useState } from "react";
import { ArrowLeft, LayoutList, Pencil, Plus, Star, Trash2, Ungroup } from "lucide-react";
import type { AccountWithRelations, ProjectWithRelations, ViewMode } from "../../types";
import { Avatar } from "../ui/Avatar";
import { Button } from "../ui/Button";
import { AccountsBoard } from "../accounts/AccountsBoard";
import { PlatformIcon } from "../ui/PlatformIcon";
import { useTranslation } from "../../i18n";

interface Props {
  project: ProjectWithRelations;
  accounts: AccountWithRelations[];
  viewMode: ViewMode;
  onBack: () => void;
  onEdit: () => void;
  onToggleFavorite: () => void;
  onDelete: () => void;
  onOpenAccountDetail: (account: AccountWithRelations) => void;
  onEditAccount: (account: AccountWithRelations) => void;
  onToggleAccountFavorite: (account: AccountWithRelations) => void;
  onAddAccount: () => void;
}

export function ProjectDetailView({
  project,
  accounts,
  viewMode,
  onBack,
  onEdit,
  onToggleFavorite,
  onDelete,
  onOpenAccountDetail,
  onEditAccount,
  onToggleAccountFavorite,
  onAddAccount,
}: Props) {
  const { t, tc } = useTranslation();
  const [grouped, setGrouped] = useState(true);

  const platformGroups = useMemo(() => {
    const map = new Map<string, { icon: string | null; name: string; accounts: AccountWithRelations[] }>();
    for (const account of accounts) {
      const key = account.platform ? String(account.platform.id) : "none";
      const group = map.get(key) ?? { icon: account.platform?.icon ?? null, name: account.platform?.name ?? t("projects.detail.noPlatform"), accounts: [] };
      group.accounts.push(account);
      map.set(key, group);
    }
    return Array.from(map.values());
  }, [accounts, t]);

  const platformCount = new Set(accounts.map((a) => a.platform_id).filter(Boolean)).size;

  return (
    <div className="p-6">
      <button onClick={onBack} className="mb-4 flex items-center gap-1.5 text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text)]">
        <ArrowLeft size={14} /> {t("projects.detail.back")}
      </button>

      <div
        className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6"
        style={project.color ? { borderTopColor: project.color, borderTopWidth: 4 } : undefined}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <Avatar imageId={project.avatar_image_id} size={64} />
            <div>
              <h1 className="text-xl font-semibold text-[var(--color-text)]">{project.name}</h1>
              {project.description && <p className="mt-1 text-sm text-[var(--color-text-muted)]">{project.description}</p>}
              <p className="mt-1.5 text-xs text-[var(--color-text-muted)]">
                {tc("common.accountsCount", accounts.length)} · {tc("common.platformsCount", platformCount)}
              </p>
              {project.tags.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {project.tags.map((tag) => (
                    <span key={tag.id} className="rounded-full bg-[var(--color-surface-hover)] px-2 py-0.5 text-[11px] text-[var(--color-text-muted)]">
                      {tag.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            <Button variant="secondary" size="sm" onClick={onEdit}>
              <Pencil size={13} /> {t("projects.detail.edit")}
            </Button>
            <Button variant="secondary" size="sm" onClick={onToggleFavorite}>
              <Star size={13} fill={project.favorite ? "currentColor" : "none"} className={project.favorite ? "text-amber-400" : ""} /> {t("projects.detail.favorite")}
            </Button>
            <Button variant="danger" size="sm" onClick={onDelete}>
              <Trash2 size={13} /> {t("projects.detail.delete")}
            </Button>
          </div>
        </div>
        {project.notes && <p className="mt-4 border-t border-[var(--color-border)] pt-3 text-sm text-[var(--color-text-muted)]">{project.notes}</p>}
      </div>

      <div className="mt-6 flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">{t("projects.detail.accountsHeading")}</p>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => setGrouped((g) => !g)}>
            {grouped ? <Ungroup size={13} /> : <LayoutList size={13} />} {grouped ? t("projects.detail.ungroup") : t("projects.detail.group")}
          </Button>
          <Button variant="primary" size="sm" onClick={onAddAccount}>
            <Plus size={13} /> {t("projects.detail.addAccount")}
          </Button>
        </div>
      </div>

      <div className="mt-3">
        {accounts.length === 0 ? (
          <p className="rounded-xl border border-dashed border-[var(--color-border)] p-8 text-center text-sm text-[var(--color-text-muted)]">
            {t("projects.detail.noneYet")}
          </p>
        ) : grouped ? (
          <div className="space-y-6">
            {platformGroups.map((group) => (
              <div key={group.name}>
                <div className="mb-2 flex items-center gap-2 text-sm font-medium text-[var(--color-text)]">
                  <PlatformIcon icon={group.icon} size={16} /> {group.name}
                </div>
                <AccountsBoard
                  accounts={group.accounts}
                  viewMode={viewMode}
                  onOpenDetail={onOpenAccountDetail}
                  onEdit={onEditAccount}
                  onToggleFavorite={onToggleAccountFavorite}
                  emptyTitle=""
                  emptyDescription=""
                  onAddAccount={onAddAccount}
                />
              </div>
            ))}
          </div>
        ) : (
          <AccountsBoard
            accounts={accounts}
            viewMode={viewMode}
            onOpenDetail={onOpenAccountDetail}
            onEdit={onEditAccount}
            onToggleFavorite={onToggleAccountFavorite}
            emptyTitle=""
            emptyDescription=""
            onAddAccount={onAddAccount}
          />
        )}
      </div>
    </div>
  );
}
