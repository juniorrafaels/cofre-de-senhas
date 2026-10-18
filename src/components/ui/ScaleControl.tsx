import { Minus, Plus } from "lucide-react";
import { LIST_SCALE_LEVELS, type ListScale } from "../../types";
import { useTranslation } from "../../i18n";

interface Props {
  scale: ListScale;
  onChange: (scale: ListScale) => void;
}

/// Controle de zoom das listagens/cards (contas e projetos) — níveis discretos, nunca zoom
/// livre, para nunca produzir um layout quebrado (seção 4 do pedido de ajuste).
export function ScaleControl({ scale, onChange }: Props) {
  const { t } = useTranslation();
  const index = LIST_SCALE_LEVELS.indexOf(scale);
  const canDecrease = index > 0;
  const canIncrease = index < LIST_SCALE_LEVELS.length - 1;

  return (
    <div className="flex items-center gap-0.5 rounded-lg border border-[var(--color-border)] px-1 py-0.5" title={t("layout.topbar.scaleControlTitle")}>
      <button
        onClick={() => canDecrease && onChange(LIST_SCALE_LEVELS[index - 1])}
        disabled={!canDecrease}
        title={t("layout.topbar.decrease")}
        className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-40"
      >
        <Minus size={14} />
      </button>
      <span className="w-11 text-center text-xs tabular-nums text-[var(--color-text-muted)]">{scale}%</span>
      <button
        onClick={() => canIncrease && onChange(LIST_SCALE_LEVELS[index + 1])}
        disabled={!canIncrease}
        title={t("layout.topbar.increase")}
        className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-40"
      >
        <Plus size={14} />
      </button>
    </div>
  );
}
