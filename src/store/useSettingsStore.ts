import { create } from "zustand";
import { getAllSettings, setSetting } from "../lib/db";
import { DEFAULT_LOCALE, useLocaleStore } from "../i18n";
import {
  DEFAULT_LIST_COLUMNS,
  LIST_SCALE_LEVELS,
  isValidLocale,
  type AppSettings,
  type ListColumnKey,
  type ListScale,
  type Locale,
  type ThemePreference,
  type ViewMode,
} from "../types";

const DEFAULTS: AppSettings = {
  theme: "system",
  language: DEFAULT_LOCALE,
  autoLockMinutes: 5,
  lockOnMinimize: false,
  clipboardClearEnabled: true,
  clipboardClearSeconds: 20,
  viewMode: "grid",
  listColumns: DEFAULT_LIST_COLUMNS,
  listScale: 100,
};

interface SettingsStore extends AppSettings {
  loaded: boolean;
  load: () => Promise<void>;
  setTheme: (theme: ThemePreference) => Promise<void>;
  setLanguage: (language: Locale) => Promise<void>;
  setAutoLockMinutes: (minutes: number) => Promise<void>;
  setLockOnMinimize: (enabled: boolean) => Promise<void>;
  setClipboardClearEnabled: (enabled: boolean) => Promise<void>;
  setClipboardClearSeconds: (seconds: number) => Promise<void>;
  setViewMode: (mode: ViewMode) => Promise<void>;
  setListColumns: (columns: ListColumnKey[]) => Promise<void>;
  setListScale: (scale: ListScale) => Promise<void>;
}

function applyTheme(theme: ThemePreference) {
  const root = document.documentElement;
  const isDark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  root.classList.toggle("dark", isDark);
}

export const useSettingsStore = create<SettingsStore>((set) => ({
  ...DEFAULTS,
  loaded: false,
  load: async () => {
    const raw = await getAllSettings();
    let listColumns = DEFAULTS.listColumns;
    if (raw.list_columns) {
      try {
        const parsed = JSON.parse(raw.list_columns);
        if (Array.isArray(parsed) && parsed.length > 0) listColumns = parsed;
      } catch {
        // ignora config corrompida, mantém o padrão
      }
    }
    const next: AppSettings = {
      theme: (raw.theme as ThemePreference) ?? DEFAULTS.theme,
      // Fallback seguro (seção 15 do pedido de i18n): um valor desconhecido/corrompido no banco
      // nunca quebra o app — sempre volta para pt-BR.
      language: isValidLocale(raw.language) ? raw.language : DEFAULTS.language,
      autoLockMinutes: raw.auto_lock_minutes ? Number(raw.auto_lock_minutes) : DEFAULTS.autoLockMinutes,
      lockOnMinimize: raw.lock_on_minimize ? raw.lock_on_minimize === "true" : DEFAULTS.lockOnMinimize,
      clipboardClearEnabled: raw.clipboard_clear_enabled ? raw.clipboard_clear_enabled === "true" : DEFAULTS.clipboardClearEnabled,
      clipboardClearSeconds: raw.clipboard_clear_seconds ? Number(raw.clipboard_clear_seconds) : DEFAULTS.clipboardClearSeconds,
      viewMode: raw.view_mode === "list" ? "list" : DEFAULTS.viewMode,
      listColumns,
      listScale: (LIST_SCALE_LEVELS as readonly number[]).includes(Number(raw.list_scale))
        ? (Number(raw.list_scale) as ListScale)
        : DEFAULTS.listScale,
    };
    applyTheme(next.theme);
    useLocaleStore.getState().setLocale(next.language);
    set({ ...next, loaded: true });
  },
  setTheme: async (theme) => {
    await setSetting("theme", theme);
    applyTheme(theme);
    set({ theme });
  },
  setLanguage: async (language) => {
    await setSetting("language", language);
    useLocaleStore.getState().setLocale(language);
    set({ language });
  },
  setLockOnMinimize: async (enabled) => {
    await setSetting("lock_on_minimize", String(enabled));
    set({ lockOnMinimize: enabled });
  },
  setAutoLockMinutes: async (minutes) => {
    await setSetting("auto_lock_minutes", String(minutes));
    set({ autoLockMinutes: minutes });
  },
  setClipboardClearEnabled: async (enabled) => {
    await setSetting("clipboard_clear_enabled", String(enabled));
    set({ clipboardClearEnabled: enabled });
  },
  setClipboardClearSeconds: async (seconds) => {
    await setSetting("clipboard_clear_seconds", String(seconds));
    set({ clipboardClearSeconds: seconds });
  },
  setViewMode: async (mode) => {
    await setSetting("view_mode", mode);
    set({ viewMode: mode });
  },
  setListColumns: async (columns) => {
    await setSetting("list_columns", JSON.stringify(columns));
    set({ listColumns: columns });
  },
  setListScale: async (scale) => {
    await setSetting("list_scale", String(scale));
    set({ listScale: scale });
  },
}));

if (typeof window !== "undefined") {
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    const { theme } = useSettingsStore.getState();
    if (theme === "system") applyTheme("system");
  });
}
