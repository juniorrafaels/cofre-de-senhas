// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buttonByText, byTestId, cleanup, flush, inputsOfType, render, submit, typeInto } from "../../test/dom";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

import { act } from "react";
import { UnlockScreen } from "../vault/UnlockScreen";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useVaultStore } from "../../store/useVaultStore";
import { useLocaleStore } from "../../i18n";
import type { UnlockGateStatus } from "../../lib/tauri";

function gate(overrides: Partial<UnlockGateStatus> = {}): UnlockGateStatus {
  return {
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
    ...overrides,
  };
}

/** Responde ao backend simulado: `unlock_gate_status` devolve o estado atual de `state.gate`. */
const state = { gate: gate(), unlockError: null as string | null };

function installBackend() {
  invoke.mockImplementation(async (command: string) => {
    if (command === "unlock_gate_status") return state.gate;
    if (command === "unlock_vault") {
      if (state.unlockError) throw state.unlockError;
      return undefined;
    }
    return undefined;
  });
}

function unlockCalls() {
  return invoke.mock.calls.filter(([command]) => command === "unlock_vault");
}

beforeEach(() => {
  invoke.mockReset();
  state.gate = gate();
  state.unlockError = null;
  installBackend();
  useSecurityStore.setState({ gate: null });
  useVaultStore.setState({ status: "locked" });
  useLocaleStore.getState().setLocale("pt-BR");
});

afterEach(async () => {
  vi.useRealTimers();
  await cleanup();
});

describe("UnlockScreen — uma senha (padrão)", () => {
  it("shows a single password field and sends only that password", async () => {
    await render(<UnlockScreen />);
    await flush();
    expect(inputsOfType("password")).toHaveLength(1);

    await typeInto(inputsOfType("password")[0], "senha-fictícia-1");
    await submit(document.querySelector("form"));
    await flush();

    expect(unlockCalls()).toEqual([["unlock_vault", { password: "senha-fictícia-1", password2: null }]]);
    expect(useVaultStore.getState().status).toBe("unlocked");
  });

  it("shows a clear message for a wrong password and clears the field", async () => {
    state.unlockError = "Senha incorreta.";
    await render(<UnlockScreen />);
    await flush();
    await typeInto(inputsOfType("password")[0], "errada-123456");
    await submit(document.querySelector("form"));
    await flush();

    expect(byTestId("unlock-error")?.textContent).toBe("Senha incorreta.");
    expect(inputsOfType("password")[0].value).toBe("");
    expect(useVaultStore.getState().status).toBe("locked");
  });

  it("does not present a protection-data error as a wrong password", async () => {
    state.unlockError = "Os dados de proteção do cofre estão corrompidos ou usam um formato não suportado.";
    await render(<UnlockScreen />);
    await flush();
    await typeInto(inputsOfType("password")[0], "qualquer-senha-1");
    await submit(document.querySelector("form"));
    await flush();
    const text = byTestId("unlock-error")?.textContent ?? "";
    expect(text).toMatch(/corrompidos/);
    expect(text).toMatch(/não indica senha incorreta/);
  });

  it("warns (without blaming the password) when the vault protection data is unreadable", async () => {
    state.gate = gate({ protection_corrupt: true });
    await render(<UnlockScreen />);
    await flush();
    expect(byTestId("protection-corrupt")?.textContent).toMatch(/não é um erro de senha/);
  });
});

describe("UnlockScreen — duas senhas", () => {
  beforeEach(() => {
    state.gate = gate({ dual: true });
  });

  it("asks for both passwords, requires both and sends both", async () => {
    await render(<UnlockScreen />);
    await flush();
    const fields = inputsOfType("password");
    expect(fields).toHaveLength(2);
    const submitButton = buttonByText("Desbloquear") ?? buttonByText(/Desbloquear|Entrar|Abrir/);
    expect(submitButton).not.toBeNull();

    await typeInto(fields[0], "primeira-senha-1");
    expect(submitButton!.disabled).toBe(true); // só a senha 1: não pode enviar
    await typeInto(fields[1], "segunda-senha-2");
    expect(submitButton!.disabled).toBe(false);

    await submit(document.querySelector("form"));
    await flush();
    expect(unlockCalls()).toEqual([["unlock_vault", { password: "primeira-senha-1", password2: "segunda-senha-2" }]]);
  });

  it("explains that two passwords are required when the backend says the second one is missing", async () => {
    state.gate = gate({ dual: false }); // a tela ainda acha que é uma senha só (estado antigo)
    state.unlockError = "E_SECOND_PASSWORD_REQUIRED";
    await render(<UnlockScreen />);
    await flush();
    await typeInto(inputsOfType("password")[0], "primeira-senha-1");
    // O backend passa a informar a política atual depois do erro.
    await submit(document.querySelector("form"));
    state.gate = gate({ dual: true });
    await flush();
    expect(byTestId("unlock-error")?.textContent).toMatch(/duas senhas/);
  });
});

describe("UnlockScreen — bloqueio progressivo", () => {
  it("shows the remaining wait, disables unlocking and counts down", async () => {
    vi.useFakeTimers();
    state.gate = gate({ throttle_enabled: true, locked: true, remaining_seconds: 90, failed_count: 4 });
    await render(<UnlockScreen />);
    await flush();

    const banner = byTestId("lockout-banner");
    expect(banner?.textContent).toContain("1 min 30 s");
    expect(banner?.textContent).toContain("4"); // tentativas incorretas seguidas
    expect(inputsOfType("password")[0].disabled).toBe(true);
    expect(buttonByText(/Desbloquear|Entrar|Abrir/)?.disabled).toBe(true);

    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });
    expect(byTestId("lockout-banner")?.textContent).toContain("1 min");
    expect(byTestId("lockout-banner")?.textContent).not.toContain("1 min 30 s");
  });

  it("refreshes the state from the backend when the wait ends, re-enabling the form", async () => {
    vi.useFakeTimers();
    state.gate = gate({ throttle_enabled: true, locked: true, remaining_seconds: 15, failed_count: 1 });
    await render(<UnlockScreen />);
    await flush();
    expect(byTestId("lockout-banner")).not.toBeNull();

    state.gate = gate({ throttle_enabled: true, locked: false, remaining_seconds: 0, failed_count: 1 }); // o backend liberou
    await act(async () => {
      vi.advanceTimersByTime(16_000);
    });
    await flush();
    expect(byTestId("lockout-banner")).toBeNull();
    expect(inputsOfType("password")[0].disabled).toBe(false);
  });

  it("a locked response from the backend shows the wait time and replaces the state with the backend's", async () => {
    state.gate = gate({ throttle_enabled: true });
    await render(<UnlockScreen />);
    await flush();
    await typeInto(inputsOfType("password")[0], "errada-123456");
    // O backend contabilizou a falha e agora informa o bloqueio de 15 s.
    state.unlockError = "E_LOCKED:15:1";
    state.gate = gate({ throttle_enabled: true, locked: true, remaining_seconds: 15, failed_count: 1 });
    await submit(document.querySelector("form"));
    await flush();

    expect(byTestId("unlock-error")?.textContent).toMatch(/15 s/);
    expect(byTestId("lockout-banner")).not.toBeNull();
    expect(buttonByText(/Desbloquear|Entrar|Abrir/)?.disabled).toBe(true);
  });

  it("never sends an unlock request while locked, even if the form is submitted programmatically", async () => {
    state.gate = gate({ throttle_enabled: true, locked: true, remaining_seconds: 60, failed_count: 3 });
    await render(<UnlockScreen />);
    await flush();
    await submit(document.querySelector("form"));
    await flush();
    expect(unlockCalls()).toHaveLength(0);
  });
});

describe("UnlockScreen — outro cofre já aberto", () => {
  it("blocks the attempt and informs that a vault is already open elsewhere", async () => {
    state.gate = gate({ open_elsewhere: true });
    await render(<UnlockScreen />);
    await flush();
    expect(byTestId("open-elsewhere")?.textContent).toMatch(/já existe um cofre aberto/i);
    expect(inputsOfType("password")[0].disabled).toBe(true);

    await submit(document.querySelector("form"));
    await flush();
    expect(unlockCalls()).toHaveLength(0);
  });

  it("explains the situation if the backend refuses the unlock because another instance opened first", async () => {
    await render(<UnlockScreen />);
    await flush();
    await typeInto(inputsOfType("password")[0], "senha-fictícia-1");
    state.unlockError = "E_VAULT_OPEN_ELSEWHERE";
    state.gate = gate({ open_elsewhere: true });
    await submit(document.querySelector("form"));
    await flush();
    expect(byTestId("unlock-error")?.textContent).toMatch(/já existe um cofre aberto/i);
    expect(byTestId("open-elsewhere")).not.toBeNull();
    expect(useVaultStore.getState().status).toBe("locked");
  });

  it("frees the screen once the other instance locks its vault (state is re-polled)", async () => {
    vi.useFakeTimers();
    state.gate = gate({ open_elsewhere: true });
    await render(<UnlockScreen />);
    await flush();
    expect(byTestId("open-elsewhere")).not.toBeNull();

    state.gate = gate({ open_elsewhere: false });
    await act(async () => {
      vi.advanceTimersByTime(3500);
    });
    await flush();
    expect(byTestId("open-elsewhere")).toBeNull();
    expect(inputsOfType("password")[0].disabled).toBe(false);
  });
});

describe("UnlockScreen — política desconhecida pela tela", () => {
  it("shows the second password field when the backend demands it even if the state query failed", async () => {
    // A consulta de estado falha (nunca devolve a política), mas o desbloqueio informa que falta a 2ª senha.
    invoke.mockImplementation(async (command: string) => {
      if (command === "unlock_gate_status") throw "falha ao consultar";
      if (command === "unlock_vault") throw "E_SECOND_PASSWORD_REQUIRED";
      return undefined;
    });
    await render(<UnlockScreen />);
    await flush();
    expect(inputsOfType("password")).toHaveLength(1);
    await typeInto(inputsOfType("password")[0], "primeira-senha-1");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(inputsOfType("password")).toHaveLength(2);
    expect(byTestId("unlock-error")?.textContent).toMatch(/duas senhas/);
  });
});
