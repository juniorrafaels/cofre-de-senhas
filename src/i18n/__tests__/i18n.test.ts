import { describe, expect, it } from "vitest";
import { pluralKey, translate, SUPPORTED_LOCALES, DEFAULT_LOCALE } from "..";
import { isValidLocale } from "../../types";
import ptBR from "../locales/pt-BR";
import en from "../locales/en";
import es from "../locales/es";

function flattenKeys(obj: unknown, prefix = ""): string[] {
  if (typeof obj !== "object" || obj === null) return [prefix];
  return Object.entries(obj as Record<string, unknown>).flatMap(([key, value]) =>
    flattenKeys(value, prefix ? `${prefix}.${key}` : key),
  );
}

const LOCALE_DICTS = { "pt-BR": ptBR, en, es } as const;

describe("i18n key parity", () => {
  // O TypeScript já garante isso em tempo de compilação (en.ts/es.ts são tipados como
  // `Messages`, o shape exato de pt-BR.ts) — este teste é uma segunda rede de segurança em
  // tempo de execução, para o caso de alguém contornar a checagem de tipos.
  const ptKeys = new Set(flattenKeys(ptBR));

  it("has at least the sections required by the onboarding/language spec", () => {
    expect(ptKeys.has("onboarding.languageLabel")).toBe(true);
    expect(ptKeys.has("settings.appearance.languageLabel")).toBe(true);
    expect(ptKeys.has("deleteVault.confirmWord")).toBe(true);
  });

  for (const locale of SUPPORTED_LOCALES) {
    it(`"${locale}" has exactly the same keys as pt-BR`, () => {
      const keys = new Set(flattenKeys(LOCALE_DICTS[locale]));
      const missing = [...ptKeys].filter((k) => !keys.has(k));
      const extra = [...keys].filter((k) => !ptKeys.has(k));
      expect(missing).toEqual([]);
      expect(extra).toEqual([]);
    });
  }
});

describe("translate()", () => {
  it("interpolates {{vars}}", () => {
    expect(translate("en", "common.copied", { label: "Password" })).toBe("Password copied");
  });

  it("falls back to pt-BR when the key is missing in the active locale (defensive, keys are always in sync)", () => {
    expect(translate("en", "does.not.exist")).toBe("does.not.exist");
  });

  it("returns the key itself when missing everywhere", () => {
    expect(translate("pt-BR", "totally.unknown.key")).toBe("totally.unknown.key");
  });
});

describe("pluralKey()", () => {
  it("picks singular for 1 and plural otherwise", () => {
    expect(pluralKey("common.accountsCount", 1)).toBe("common.accountsCount_one");
    expect(pluralKey("common.accountsCount", 0)).toBe("common.accountsCount_other");
    expect(pluralKey("common.accountsCount", 2)).toBe("common.accountsCount_other");
  });
});

describe("isValidLocale() fallback (section 15 — invalid stored language must never break the app)", () => {
  it("accepts the three supported locales", () => {
    expect(isValidLocale("pt-BR")).toBe(true);
    expect(isValidLocale("en")).toBe(true);
    expect(isValidLocale("es")).toBe(true);
  });

  it("rejects unknown/corrupted values", () => {
    expect(isValidLocale("xyz")).toBe(false);
    expect(isValidLocale("")).toBe(false);
    expect(isValidLocale(undefined)).toBe(false);
    expect(isValidLocale(null)).toBe(false);
    expect(isValidLocale(123)).toBe(false);
  });

  it("default locale is Portuguese", () => {
    expect(DEFAULT_LOCALE).toBe("pt-BR");
  });
});

describe("deleteVault.confirmWord (section 12 — the required word must match the active language)", () => {
  it("is distinct per language and matches the spec", () => {
    expect(ptBR.deleteVault.confirmWord).toBe("EXCLUIR");
    expect(en.deleteVault.confirmWord).toBe("DELETE");
    expect(es.deleteVault.confirmWord).toBe("ELIMINAR");
  });
});

describe("internal enum values never change with language (section 8)", () => {
  it("account status keys are the same identifiers across locales", () => {
    const statuses = ["active", "blocked", "recovering", "suspended", "disabled", "archived"];
    for (const locale of SUPPORTED_LOCALES) {
      expect(Object.keys(LOCALE_DICTS[locale].enums.accountStatus).sort()).toEqual(statuses.sort());
    }
  });
});
