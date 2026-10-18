import { type AccountStatus } from "../../types";
import { useTranslation } from "../../i18n";
import { accountStatusLabel } from "../../i18n/enumLabels";

const STATUS_COLORS: Record<AccountStatus, string> = {
  active: "bg-[var(--color-success)]",
  blocked: "bg-[var(--color-danger)]",
  recovering: "bg-amber-500",
  suspended: "bg-amber-500",
  disabled: "bg-[var(--color-text-muted)]",
  archived: "bg-[var(--color-text-muted)]",
};

export function StatusBadge({ status }: { status: AccountStatus }) {
  const { t } = useTranslation();
  if (status === "active") return null;
  return (
    <span className="flex items-center gap-1 rounded-full bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-muted)]">
      <span className={`h-1.5 w-1.5 rounded-full ${STATUS_COLORS[status]}`} />
      {accountStatusLabel(t, status)}
    </span>
  );
}
