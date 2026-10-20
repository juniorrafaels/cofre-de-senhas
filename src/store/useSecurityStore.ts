import { create } from "zustand";
import { unlockPolicyCommands, type UnlockGateStatus } from "../lib/tauri";

/** Estado neutro usado quando o backend ainda não respondeu (política padrão: uma senha, sem bloqueio). */
export const EMPTY_GATE: UnlockGateStatus = {
  initialized: true,
  unlocked: false,
  dual: false,
  throttle_enabled: false,
  locked: false,
  remaining_seconds: 0,
  failed_count: 0,
  open_elsewhere: false,
  recovery_password_enabled: false,
  protection_corrupt: false,
};

interface SecurityStore {
  /** Último estado público conhecido (política de senhas, bloqueio progressivo, instância aberta). */
  gate: UnlockGateStatus | null;
  refresh: () => Promise<UnlockGateStatus | null>;
}

export const useSecurityStore = create<SecurityStore>((set) => ({
  gate: null,
  refresh: async () => {
    try {
      const gate = await unlockPolicyCommands.gateStatus();
      set({ gate });
      return gate;
    } catch {
      // Falha ao consultar não derruba a tela: mantém o último estado conhecido. O backend segue
      // sendo quem aplica as regras (ex.: devolve E_SECOND_PASSWORD_REQUIRED se faltar a 2ª senha).
      return null;
    }
  },
}));
