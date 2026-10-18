import { ArrowDown, ArrowUp } from "lucide-react";
import { ALL_LIST_COLUMNS, type ListColumnKey } from "../../types";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useTranslation } from "../../i18n";
import { listColumnLabel } from "../../i18n/enumLabels";

export function ListColumnsConfig() {
  const { t } = useTranslation();
  const listColumns = useSettingsStore((s) => s.listColumns);
  const setListColumns = useSettingsStore((s) => s.setListColumns);

  function toggle(col: ListColumnKey) {
    if (listColumns.includes(col)) {
      setListColumns(listColumns.filter((c) => c !== col));
    } else {
      setListColumns([...listColumns, col]);
    }
  }

  function move(col: ListColumnKey, direction: -1 | 1) {
    const index = listColumns.indexOf(col);
    const newIndex = index + direction;
    if (newIndex < 0 || newIndex >= listColumns.length) return;
    const next = [...listColumns];
    [next[index], next[newIndex]] = [next[newIndex], next[index]];
    setListColumns(next);
  }

  const unselected = ALL_LIST_COLUMNS.filter((c) => !listColumns.includes(c));

  return (
    <div className="space-y-3">
      <p className="text-xs text-[var(--color-text-muted)]">{t("settings.listColumns.hint")}</p>
      <div className="space-y-1">
        {listColumns.map((col) => (
          <div key={col} className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-2.5 py-1.5">
            <input type="checkbox" checked onChange={() => toggle(col)} className="h-4 w-4 rounded border-[var(--color-border)]" />
            <span className="flex-1 text-sm text-[var(--color-text)]">{listColumnLabel(t, col)}</span>
            <button onClick={() => move(col, -1)} className="rounded-md p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
              <ArrowUp size={13} />
            </button>
            <button onClick={() => move(col, 1)} className="rounded-md p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
              <ArrowDown size={13} />
            </button>
          </div>
        ))}
        {unselected.map((col) => (
          <label key={col} className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 opacity-60 hover:opacity-100">
            <input type="checkbox" checked={false} onChange={() => toggle(col)} className="h-4 w-4 rounded border-[var(--color-border)]" />
            <span className="flex-1 text-sm text-[var(--color-text)]">{listColumnLabel(t, col)}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
