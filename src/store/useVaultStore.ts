import { create } from "zustand";
import { vaultCommands } from "../lib/tauri";
import type { VaultStatusKind } from "../types";

interface VaultStore {
  status: VaultStatusKind;
  refresh: () => Promise<void>;
  create: (password: string) => Promise<void>;
  unlock: (password: string, password2?: string) => Promise<void>;
  lock: () => Promise<void>;
}

export const useVaultStore = create<VaultStore>((set) => ({
  status: "loading",
  refresh: async () => {
    const result = await vaultCommands.status();
    set({ status: !result.initialized ? "uninitialized" : result.unlocked ? "unlocked" : "locked" });
  },
  create: async (password: string) => {
    await vaultCommands.create(password);
    set({ status: "unlocked" });
  },
  unlock: async (password: string, password2?: string) => {
    await vaultCommands.unlock(password, password2);
    set({ status: "unlocked" });
  },
  lock: async () => {
    await vaultCommands.lock();
    set({ status: "locked" });
  },
}));
