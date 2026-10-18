import { useEffect, useState } from "react";
import { listAccountHistory } from "../../lib/db";
import type { AccountHistoryEntry } from "../../types";
import { useTranslation } from "../../i18n";

function historyEventLabel(t: (key: string) => string, event: string): string {
  const key = `accounts.history.events.${event}`;
  const label = t(key);
  return label === key ? event : label;
}

export function AccountHistorySection({ accountId }: { accountId: number }) {
  const { t, intlLocale } = useTranslation();
  const [entries, setEntries] = useState<AccountHistoryEntry[]>([]);

  useEffect(() => {
    listAccountHistory(accountId).then(setEntries);
  }, [accountId]);

  if (entries.length === 0) {
    return <p className="text-sm text-[var(--color-text-muted)]">{t("accounts.history.empty")}</p>;
  }

  return (
    <div className="space-y-3">
      {entries.map((entry) => (
        <div key={entry.id} className="border-l-2 border-[var(--color-border)] pl-3">
          <p className="text-xs text-[var(--color-text-muted)]">{new Date(entry.created_at).toLocaleString(intlLocale)}</p>
          <p className="text-sm text-[var(--color-text)]">{historyEventLabel(t, entry.event)}</p>
          {entry.detail && <p className="text-xs text-[var(--color-text-muted)]">{entry.detail}</p>}
        </div>
      ))}
    </div>
  );
}
