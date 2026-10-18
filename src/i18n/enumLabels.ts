import type { AccountStatus, ListColumnKey, PropertyType, TwoFactorMethod } from "../types";

type T = (key: string, vars?: Record<string, string | number>) => string;

// Os valores internos (AccountStatus, TwoFactorMethod, etc.) nunca mudam com o idioma — só o
// label exibido. Ver seção 8/9 do pedido de i18n: nunca persistir o texto traduzido como valor de
// negócio.
export function accountStatusLabel(t: T, status: AccountStatus): string {
  return t(`enums.accountStatus.${status}`);
}

export function twoFactorMethodLabel(t: T, method: TwoFactorMethod): string {
  return t(`enums.twoFactorMethod.${method}`);
}

export function propertyTypeLabel(t: T, type: PropertyType): string {
  return t(`enums.propertyType.${type}`);
}

export function listColumnLabel(t: T, column: ListColumnKey): string {
  return t(`enums.listColumn.${column}`);
}
