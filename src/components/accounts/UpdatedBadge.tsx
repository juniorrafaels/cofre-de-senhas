import { BadgeCheck } from "lucide-react";
import { getUpdateBadge } from "../../lib/accountBadge";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useTranslation } from "../../i18n";

interface Props {
  /** Instante UTC da última confirmação manual (`update_confirmed_at`), se houver. */
  confirmedAt: string | null | undefined;
  /** Relógio injetável (testes); por padrão `Date.now()`. */
  nowMs?: number;
  /** Ignora a preferência de exibição (ex.: pré-visualização). Normalmente não usar. */
  force?: boolean;
}

/**
 * Selo "Atualizada". Só aparece dentro da validade de 90 dias e se a preferência de exibição
 * estiver ligada. Passados os 90 dias (ou com data ausente/inválida/futura) nada é renderizado.
 * Exibir, editar ou abrir a conta nunca renova o selo — só a ação explícita "Marcar como atualizada".
 */
export function UpdatedBadge({ confirmedAt, nowMs, force }: Props) {
  const { t, intlLocale } = useTranslation();
  const show = useSettingsStore((s) => s.showUpdatedBadge);
  if (!force && !show) return null;
  const state = getUpdateBadge(confirmedAt, nowMs ?? Date.now());
  if (state.status !== "valid") return null;
  const title = t("accounts.updateBadge.validTooltip", {
    date: state.confirmedAt.toLocaleDateString(intlLocale),
    expires: state.expiresAt.toLocaleDateString(intlLocale),
    days: state.daysLeft,
  });
  return (
    <span
      data-testid="updated-badge"
      title={title}
      className="inline-flex items-center gap-1 rounded-full bg-[var(--color-success)]/15 px-2 py-0.5 text-[11px] font-medium text-[var(--color-success)]"
    >
      <BadgeCheck size={11} aria-hidden="true" />
      {t("accounts.updateBadge.label")}
    </span>
  );
}
