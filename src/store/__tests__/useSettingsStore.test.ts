// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// jsdom não implementa `matchMedia` — useSettingsStore.ts o usa para reagir a mudanças no tema do
// SO (fora do escopo desta tarefa de i18n). Um stub mínimo é suficiente para o módulo carregar.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

const dbState: { settings: Record<string, string> } = { settings: {} };

// `useSettingsStore.load()` chama `getAllSettings`/`setSetting` (src/lib/db.ts), que por sua vez
// invocam commands do Tauri via `@tauri-apps/api/core`. Mockar só a fronteira do banco (em vez do
// Tauri inteiro) mantém o teste focado na lógica de idioma/fallback do store, que é o que a
// seção 16 do pedido de i18n pede para validar.
vi.mock("../../lib/db", () => ({
  getAllSettings: vi.fn(async () => dbState.settings),
  setSetting: vi.fn(async (key: string, value: string) => {
    dbState.settings[key] = value;
  }),
}));

describe("useSettingsStore — language preference (section 16 do pedido de i18n)", () => {
  beforeEach(() => {
    dbState.settings = {};
    vi.resetModules();
  });

  afterEach(() => {
    vi.resetModules();
  });

  it("defaults to Portuguese before load() runs and after loading an empty settings table", async () => {
    const { useSettingsStore } = await import("../useSettingsStore");
    expect(useSettingsStore.getState().language).toBe("pt-BR");

    await useSettingsStore.getState().load();
    expect(useSettingsStore.getState().language).toBe("pt-BR");
  });

  it("persists a chosen language and keeps it after reloading (simulates close/reopen)", async () => {
    const { useSettingsStore } = await import("../useSettingsStore");
    const { useLocaleStore } = await import("../../i18n");

    await useSettingsStore.getState().setLanguage("en");
    expect(dbState.settings.language).toBe("en");
    expect(useLocaleStore.getState().locale).toBe("en");

    // "Fecha e abre de novo": um novo load() a partir do valor persistido deve manter "en".
    await useSettingsStore.getState().load();
    expect(useSettingsStore.getState().language).toBe("en");
    expect(useLocaleStore.getState().locale).toBe("en");
  });

  it("falls back to Portuguese when the stored language is invalid/unknown (section 15)", async () => {
    dbState.settings.language = "xx-not-a-real-locale";
    const { useSettingsStore } = await import("../useSettingsStore");

    await useSettingsStore.getState().load();
    expect(useSettingsStore.getState().language).toBe("pt-BR");
  });

  it("switching to Spanish in Settings updates the store immediately", async () => {
    const { useSettingsStore } = await import("../useSettingsStore");
    const { useLocaleStore } = await import("../../i18n");

    await useSettingsStore.getState().setLanguage("es");
    expect(useSettingsStore.getState().language).toBe("es");
    expect(useLocaleStore.getState().locale).toBe("es");
  });
});

describe("useSettingsStore — preferências de exibição de último login e selo \"Atualizada\"", () => {
  beforeEach(() => {
    dbState.settings = {};
    vi.resetModules();
  });

  it("shows the badge by default and does not add the last-login column to existing layouts", async () => {
    const { useSettingsStore } = await import("../useSettingsStore");
    await useSettingsStore.getState().load();
    expect(useSettingsStore.getState().showUpdatedBadge).toBe(true);
    expect(useSettingsStore.getState().listColumns).not.toContain("last_login");
  });

  it("persists the badge preference separately from the column list, and restores both after reopening", async () => {
    const { useSettingsStore } = await import("../useSettingsStore");
    await useSettingsStore.getState().setShowUpdatedBadge(false);
    await useSettingsStore.getState().setListColumns(["name", "last_login"]);
    expect(dbState.settings.show_updated_badge).toBe("false");
    expect(dbState.settings.list_columns).toBe('["name","last_login"]');

    await useSettingsStore.getState().load(); // "fecha e abre de novo"
    expect(useSettingsStore.getState().showUpdatedBadge).toBe(false);
    expect(useSettingsStore.getState().listColumns).toEqual(["name", "last_login"]);

    await useSettingsStore.getState().setShowUpdatedBadge(true);
    expect(useSettingsStore.getState().listColumns).toEqual(["name", "last_login"]); // independentes
  });
});
