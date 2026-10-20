import { evaluatePasswordStrength, MAX_STRENGTH_SCORE, type StrengthLevel } from "../../lib/passwordStrength";
import { useTranslation } from "../../i18n";

const LEVEL_COLOR: Record<StrengthLevel, string> = {
  veryWeak: "bg-[var(--color-danger)]",
  weak: "bg-[var(--color-danger)]",
  fair: "bg-amber-500",
  strong: "bg-[var(--color-success)]",
  veryStrong: "bg-[var(--color-success)]",
};

interface Props {
  password: string;
  /**
   * `"five"` (padrão): muito fraca / fraca / razoável / forte / muito forte — usado nas senhas das
   * contas. `"three"`: o agrupamento Fraca / Razoável / Forte da tela da senha mestra.
   */
  granularity?: "five" | "three";
}

/**
 * Indicador de força que atualiza a cada tecla (puro e local — ver `lib/passwordStrength.ts`).
 * Só informa: não altera a senha e não impede salvar. Nada é enviado, gravado ou logado.
 */
export function PasswordStrengthMeter({ password, granularity = "five" }: Props) {
  const { t } = useTranslation();
  if (!password) return null;
  const { score, level } = evaluatePasswordStrength(password);
  const labelKey =
    granularity === "three"
      ? level === "veryWeak" || level === "weak"
        ? "onboarding.strengthWeak"
        : level === "fair"
          ? "onboarding.strengthFair"
          : "onboarding.strengthStrong"
      : `security.strength.${level}`;
  const label = t(labelKey);
  return (
    <div className="mt-1.5 flex items-center gap-2" data-testid="password-strength" data-level={level}>
      <div
        className="h-1 flex-1 overflow-hidden rounded-full bg-[var(--color-border)]"
        role="meter"
        aria-label={t("security.strength.meterLabel")}
        aria-valuemin={0}
        aria-valuemax={MAX_STRENGTH_SCORE}
        aria-valuenow={score}
        aria-valuetext={label}
      >
        <div className={`h-full ${LEVEL_COLOR[level]} transition-all`} style={{ width: `${(score / MAX_STRENGTH_SCORE) * 100}%` }} />
      </div>
      <span className="text-xs text-[var(--color-text-muted)]" aria-live="polite">
        {label}
      </span>
    </div>
  );
}
