import { LayoutGrid, List, Plus, Search } from "lucide-react";
import { Button } from "../ui/Button";
import { ScaleControl } from "../ui/ScaleControl";
import { useTranslation } from "../../i18n";
import type { ListScale, ViewMode } from "../../types";

interface Props {
  title: string;
  search: string;
  onSearchChange: (value: string) => void;
  onAddAccount: () => void;
  viewMode: ViewMode;
  onViewModeChange: (mode: ViewMode) => void;
  listScale: ListScale;
  onListScaleChange: (scale: ListScale) => void;
  searchPlaceholder?: string;
  addLabel?: string;
}

export function TopBar({
  title,
  search,
  onSearchChange,
  onAddAccount,
  viewMode,
  onViewModeChange,
  listScale,
  onListScaleChange,
  searchPlaceholder,
  addLabel,
}: Props) {
  const { t } = useTranslation();
  return (
    <div className="flex shrink-0 items-center justify-between gap-4 border-b border-[var(--color-border)] px-6 py-4">
      <h1 className="text-lg font-semibold text-[var(--color-text)]">{title}</h1>
      <div className="flex items-center gap-3">
        <div className="relative">
          <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
          <input
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder={searchPlaceholder ?? t("layout.topbar.searchPlaceholder")}
            className="w-64 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-2 pl-9 pr-3 text-sm outline-none transition-shadow focus:ring-2 focus:ring-[var(--color-accent)]/40 focus:border-[var(--color-accent)]"
          />
        </div>
        <div className="flex rounded-lg border border-[var(--color-border)] p-0.5">
          <button
            onClick={() => onViewModeChange("grid")}
            title={t("layout.topbar.gridView")}
            className={`rounded-md p-1.5 ${viewMode === "grid" ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]" : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"}`}
          >
            <LayoutGrid size={15} />
          </button>
          <button
            onClick={() => onViewModeChange("list")}
            title={t("layout.topbar.listView")}
            className={`rounded-md p-1.5 ${viewMode === "list" ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)]" : "text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"}`}
          >
            <List size={15} />
          </button>
        </div>
        <ScaleControl scale={listScale} onChange={onListScaleChange} />
        <Button variant="primary" onClick={onAddAccount}>
          <Plus size={16} /> {addLabel ?? t("layout.topbar.addAccount")}
        </Button>
      </div>
    </div>
  );
}
