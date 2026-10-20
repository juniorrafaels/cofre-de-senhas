// Selo "Atualizada" das contas. A validade é de 90 dias EXATOS (90 × 24 h) contados a partir do
// instante UTC da última confirmação manual — a conta é feita sobre instantes (epoch em ms), nunca
// sobre o calendário local, então fuso e horário de verão não deslocam o prazo. Só a EXIBIÇÃO usa
// o fuso local. Mesmas regras do backend (`src-tauri/src/account_status.rs`).

export const BADGE_VALIDITY_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;
/** Tolerância para pequenas diferenças de relógio; além disso uma data futura é inválida. */
export const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

export type UpdateBadgeState =
  | { status: "none" }
  | { status: "valid"; confirmedAt: Date; expiresAt: Date; daysLeft: number }
  | { status: "expired"; confirmedAt: Date; expiredAt: Date };

/** RFC 3339 com fuso explícito; qualquer outra coisa (inclusive só a data) é inválida. */
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export function parseConfirmation(value: string | null | undefined): Date | null {
  if (!value || !RFC3339.test(value.trim())) return null;
  const ms = Date.parse(value.trim());
  return Number.isNaN(ms) ? null : new Date(ms);
}

export function getUpdateBadge(confirmedAt: string | null | undefined, nowMs: number = Date.now()): UpdateBadgeState {
  const confirmed = parseConfirmation(confirmedAt);
  if (!confirmed) return { status: "none" };
  if (confirmed.getTime() > nowMs + FUTURE_TOLERANCE_MS) return { status: "none" };
  const expiresMs = confirmed.getTime() + BADGE_VALIDITY_DAYS * DAY_MS;
  if (nowMs < expiresMs) {
    return {
      status: "valid",
      confirmedAt: confirmed,
      expiresAt: new Date(expiresMs),
      daysLeft: Math.ceil((expiresMs - nowMs) / DAY_MS),
    };
  }
  return { status: "expired", confirmedAt: confirmed, expiredAt: new Date(expiresMs) };
}

/**
 * Data do último login para exibição. Data pura (`YYYY-MM-DD`) é mostrada como data de calendário
 * (sem conversão de fuso, para não "andar um dia"); um instante UTC é convertido para o fuso local.
 */
export function formatLastLogin(value: string | null | undefined, intlLocale: string): string {
  if (!value) return "";
  const pure = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (pure) return new Date(Number(pure[1]), Number(pure[2]) - 1, Number(pure[3])).toLocaleDateString(intlLocale);
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? "" : new Date(ms).toLocaleDateString(intlLocale);
}
