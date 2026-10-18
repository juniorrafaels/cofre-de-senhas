import { create } from "zustand";
import { isValidLocale, SUPPORTED_LOCALES, type Locale } from "../types";
import ptBR from "./locales/pt-BR";
import en from "./locales/en";
import es from "./locales/es";
import type { Messages } from "./locales/pt-BR";

export type { Locale };
export { SUPPORTED_LOCALES, isValidLocale };

export const DEFAULT_LOCALE: Locale = "pt-BR";

/** Locale do `Intl`/`toLocaleDateString` correspondente a cada idioma da interface. */
export const INTL_LOCALE: Record<Locale, string> = { "pt-BR": "pt-BR", en: "en-US", es: "es-ES" };

const MESSAGES: Record<Locale, Messages> = { "pt-BR": ptBR, en, es };

type Vars = Record<string, string | number>;

function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, part) => {
    if (acc && typeof acc === "object" && part in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, obj);
}

function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{\{(\w+)\}\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match));
}

/**
 * Busca a chave `key` (dot-path, ex.: "common.cancel") no idioma pedido, com fallback para
 * `pt-BR` se a chave não existir no idioma ativo (nunca deve acontecer se os três locales forem
 * mantidos em paralelo — ver teste de paridade de chaves), e finalmente para a própria chave.
 */
export function translate(locale: Locale, key: string, vars?: Vars): string {
  const dict = MESSAGES[locale] ?? MESSAGES[DEFAULT_LOCALE];
  let value = getPath(dict, key);
  if (typeof value !== "string" && locale !== DEFAULT_LOCALE) {
    value = getPath(MESSAGES[DEFAULT_LOCALE], key);
  }
  if (typeof value !== "string") {
    if (import.meta.env?.DEV) console.warn(`[i18n] Chave de tradução ausente: ${key}`);
    return key;
  }
  return interpolate(value, vars);
}

/** Escolhe a variante singular/plural de uma chave de contagem (`<base>_one` / `<base>_other`). */
export function pluralKey(base: string, count: number): string {
  return count === 1 ? `${base}_one` : `${base}_other`;
}

interface LocaleStore {
  locale: Locale;
  setLocale: (locale: Locale) => void;
}

// Fonte única de verdade sobre o idioma ATIVO da interface — independente de estar persistido ou
// não. No onboarding (antes do cofre existir) é só isto que muda a UI; após o cofre criado,
// useSettingsStore.setLanguage() também persiste e atualiza este store. Isso garante troca
// instantânea (seção 3/5 do pedido) sem depender de um Context/Provider React.
export const useLocaleStore = create<LocaleStore>((set) => ({
  locale: DEFAULT_LOCALE,
  setLocale: (locale) => set({ locale: isValidLocale(locale) ? locale : DEFAULT_LOCALE }),
}));

export function useTranslation() {
  const locale = useLocaleStore((s) => s.locale);
  const setLocale = useLocaleStore((s) => s.setLocale);
  function t(key: string, vars?: Vars): string {
    return translate(locale, key, vars);
  }
  function tc(base: string, count: number, vars?: Vars): string {
    return translate(locale, pluralKey(base, count), { count, ...vars });
  }
  return { t, tc, locale, setLocale, intlLocale: INTL_LOCALE[locale] };
}
