// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buttonByText, byTestId, cleanup, click, flush, inputsOfType, render, submit, typeInto } from "../../test/dom";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

import { UnlockPolicySection } from "../settings/UnlockPolicySection";
import { RecoveryPasswordSection } from "../settings/RecoveryPasswordSection";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useToastStore } from "../../store/useToastStore";
import { useLocaleStore } from "../../i18n";
import type { UnlockGateStatus } from "../../lib/tauri";

const backend = {
  gate: null as unknown as UnlockGateStatus,
  recoveryPassword: { enabled: false, created_at: null as string | null },
  error: null as string | null,
};

function gate(overrides: Partial<UnlockGateStatus> = {}): UnlockGateStatus {
  return {
    initialized: true,
    unlocked: true,
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

function calls(command: string) {
  return invoke.mock.calls.filter(([c]) => c === command);
}

beforeEach(() => {
  invoke.mockReset();
  backend.gate = gate();
  backend.recoveryPassword = { enabled: false, created_at: null };
  backend.error = null;
  invoke.mockImplementation(async (command: string) => {
    if (command === "unlock_gate_status") return backend.gate;
    if (command === "recovery_password_status") return backend.recoveryPassword;
    if (
      ["enable_dual_unlock", "disable_dual_unlock", "change_second_unlock_password", "set_unlock_throttle", "set_recovery_password", "disable_recovery_password"].includes(command) &&
      backend.error
    ) {
      throw backend.error;
    }
    return undefined;
  });
  useSecurityStore.setState({ gate: null });
  useToastStore.setState({ toasts: [] } as never);
  useLocaleStore.getState().setLocale("pt-BR");
});

afterEach(async () => {
  await cleanup();
});

/** Campos de senha do modal aberto (o diálogo é um portal no body). */
function modalPasswords() {
  return inputsOfType("password");
}

describe("UnlockPolicySection — padrões e explicações", () => {
  it("both options are off by default for an existing (legacy) vault", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    expect(byTestId("dual-section")?.textContent).toMatch(/Desativado/);
    expect(byTestId("throttle-section")?.textContent).toMatch(/Desativado \(padrão\)/);
  });

  it("explains the honest limits of the lockout before the user enables it", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    const text = byTestId("throttle-section")?.textContent ?? "";
    expect(text).toMatch(/15 s/);
    expect(text).toMatch(/4 h/);
    expect(text).toMatch(/não é proteção absoluta/);
    expect(text).toMatch(/Recovery Key/);
  });
});

describe("UnlockPolicySection — ativar duas senhas", () => {
  async function openEnable() {
    await render(<UnlockPolicySection />);
    await flush();
    await click(buttonByText("Ativar duas senhas"));
    await flush();
  }

  it("shows the risk of losing a password BEFORE enabling and refuses without acknowledgement", async () => {
    await openEnable();
    const dialog = document.body.textContent ?? "";
    expect(dialog).toMatch(/Leia antes de ativar/);
    expect(dialog).toMatch(/perder UMA das duas senhas/);
    expect(dialog).toMatch(/Sem nenhum configurado, os dados ficam inacessíveis/);

    const [current, second, confirm] = modalPasswords();
    await typeInto(current, "senha-mestra-fictícia");
    await typeInto(second, "segunda-fictícia-1");
    await typeInto(confirm, "segunda-fictícia-1");
    await submit(document.querySelectorAll("form")[0]);
    await flush();
    expect(calls("enable_dual_unlock")).toHaveLength(0);
    expect(document.body.textContent).toMatch(/Confirme que entendeu os riscos/);
  });

  it("validates the second password (length, confirmation, different from the first)", async () => {
    await openEnable();
    const [current, second, confirm] = modalPasswords();
    const checkbox = document.querySelector('input[type="checkbox"]') as HTMLInputElement;
    await click(checkbox);
    await typeInto(current, "senha-mestra-fictícia");

    await typeInto(second, "curta");
    await typeInto(confirm, "curta");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).toMatch(/pelo menos 8 caracteres/);

    await typeInto(second, "segunda-fictícia-1");
    await typeInto(confirm, "outra-diferente-22");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).toMatch(/não coincidem/);

    await typeInto(second, "senha-mestra-fictícia");
    await typeInto(confirm, "senha-mestra-fictícia");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).toMatch(/diferente da primeira/);
    expect(calls("enable_dual_unlock")).toHaveLength(0);
  });

  it("shows the strength of the new second password while typing", async () => {
    await openEnable();
    const second = modalPasswords()[1];
    await typeInto(second, "abc");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("veryWeak");
    await typeInto(second, "Abcdef1!xyzK");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("veryStrong");
  });

  it("calls the backend with the current master password and the new second password, then refreshes the state", async () => {
    await openEnable();
    const [current, second, confirm] = modalPasswords();
    await click(document.querySelector('input[type="checkbox"]'));
    await typeInto(current, "senha-mestra-fictícia");
    await typeInto(second, "segunda-fictícia-1");
    await typeInto(confirm, "segunda-fictícia-1");
    backend.gate = gate({ dual: true });
    await submit(document.querySelector("form"));
    await flush(5);

    expect(calls("enable_dual_unlock")).toEqual([
      ["enable_dual_unlock", { currentPassword: "senha-mestra-fictícia", secondPassword: "segunda-fictícia-1" }],
    ]);
    expect(useSecurityStore.getState().gate?.dual).toBe(true);
    expect(byTestId("dual-section")?.textContent).toMatch(/Ativado/);
  });

  it("shows a comprehensible message when the backend rejects the current password", async () => {
    await openEnable();
    const [current, second, confirm] = modalPasswords();
    await click(document.querySelector('input[type="checkbox"]'));
    await typeInto(current, "senha-errada-1234");
    await typeInto(second, "segunda-fictícia-1");
    await typeInto(confirm, "segunda-fictícia-1");
    backend.error = "Senha incorreta.";
    await submit(document.querySelector("form"));
    await flush(5);
    expect(document.body.querySelector('[role="alert"].text-sm')?.textContent ?? document.body.textContent).toMatch(/Senha incorreta/);
    expect(byTestId("dual-section")?.textContent).toMatch(/Desativado/);
  });
});

describe("UnlockPolicySection — desativar e trocar com duas senhas ativas", () => {
  beforeEach(() => {
    backend.gate = gate({ dual: true });
  });

  it("shows the active state and the change/disable actions", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    expect(byTestId("dual-section")?.textContent).toMatch(/Ativado: o cofre só abre com as duas senhas/);
    expect(buttonByText("Trocar a segunda senha")).not.toBeNull();
    expect(buttonByText("Desativar")).not.toBeNull();
    expect(buttonByText("Ativar duas senhas")).toBeNull();
  });

  it("disabling requires BOTH current passwords and sends them", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    await click(buttonByText("Desativar"));
    await flush();
    const fields = modalPasswords();
    expect(fields).toHaveLength(2);

    await typeInto(fields[0], "senha-um-fictícia");
    await submit(document.querySelector("form"));
    await flush();
    expect(calls("disable_dual_unlock")).toHaveLength(0); // falta a segunda senha

    await typeInto(fields[1], "senha-dois-fictícia");
    backend.gate = gate({ dual: false });
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("disable_dual_unlock")).toEqual([
      ["disable_dual_unlock", { currentPassword: "senha-um-fictícia", currentPassword2: "senha-dois-fictícia" }],
    ]);
    expect(byTestId("dual-section")?.textContent).toMatch(/Desativado/);
  });

  it("changing the second password sends the current pair and the new second password", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    await click(buttonByText("Trocar a segunda senha"));
    await flush();
    const [current, current2, newSecond, confirm] = modalPasswords();
    await typeInto(current, "senha-um-fictícia");
    await typeInto(current2, "senha-dois-fictícia");
    await typeInto(newSecond, "terceira-fictícia-3");
    await typeInto(confirm, "terceira-fictícia-3");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("change_second_unlock_password")).toEqual([
      [
        "change_second_unlock_password",
        { currentPassword: "senha-um-fictícia", currentPassword2: "senha-dois-fictícia", newSecondPassword: "terceira-fictícia-3" },
      ],
    ]);
  });
});

describe("UnlockPolicySection — bloqueio progressivo", () => {
  it("enables with re-authentication and shows the new state", async () => {
    await render(<UnlockPolicySection />);
    await flush();
    await click(buttonByText("Ativar bloqueio progressivo"));
    await flush();
    await typeInto(modalPasswords()[0], "senha-mestra-fictícia");
    backend.gate = gate({ throttle_enabled: true });
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("set_unlock_throttle")).toEqual([
      ["set_unlock_throttle", { enabled: true, currentPassword: "senha-mestra-fictícia", currentPassword2: null }],
    ]);
    expect(byTestId("throttle-section")?.textContent).toMatch(/Ativado\./);
  });

  it("disables it (needs both passwords when two-password unlock is on)", async () => {
    backend.gate = gate({ dual: true, throttle_enabled: true });
    await render(<UnlockPolicySection />);
    await flush();
    await click(buttonByText("Desativar", byTestId("throttle-section")!));
    await flush();
    const fields = modalPasswords();
    expect(fields).toHaveLength(2);
    await typeInto(fields[0], "senha-um-fictícia");
    await typeInto(fields[1], "senha-dois-fictícia");
    backend.gate = gate({ dual: true, throttle_enabled: false });
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("set_unlock_throttle")).toEqual([
      ["set_unlock_throttle", { enabled: false, currentPassword: "senha-um-fictícia", currentPassword2: "senha-dois-fictícia" }],
    ]);
  });
});

describe("RecoveryPasswordSection", () => {
  it("is off by default and explains that it is independent of the other recovery methods", async () => {
    await render(<RecoveryPasswordSection />);
    await flush();
    const text = byTestId("recovery-password-section")?.textContent ?? "";
    expect(text).toMatch(/Não configurada/);
    expect(text).toMatch(/independente/);
  });

  it("warns about keeping the password safe before configuring it", async () => {
    await render(<RecoveryPasswordSection />);
    await flush();
    await click(buttonByText("Configurar"));
    await flush();
    expect(document.body.textContent).toMatch(/Guarde esta senha em lugar seguro/);
    expect(document.body.textContent).toMatch(/não há como recuperar o cofre/);
  });

  it("validates length and confirmation, then sends the current password and the new recovery password", async () => {
    await render(<RecoveryPasswordSection />);
    await flush();
    await click(buttonByText("Configurar"));
    await flush();
    const [current, newPassword, confirm] = modalPasswords();
    await typeInto(current, "senha-mestra-fictícia");

    await typeInto(newPassword, "curta");
    await typeInto(confirm, "curta");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).toMatch(/pelo menos 8 caracteres/);

    await typeInto(newPassword, "recuperacao-fictícia-1");
    await typeInto(confirm, "outra-coisa-diferente");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).toMatch(/não coincidem/);
    expect(calls("set_recovery_password")).toHaveLength(0);

    await typeInto(confirm, "recuperacao-fictícia-1");
    backend.recoveryPassword = { enabled: true, created_at: "2026-02-01T10:00:00Z" };
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("set_recovery_password")).toEqual([
      [
        "set_recovery_password",
        { currentPassword: "senha-mestra-fictícia", currentPassword2: null, newRecoveryPassword: "recuperacao-fictícia-1" },
      ],
    ]);
    expect(byTestId("recovery-password-section")?.textContent).toMatch(/Configurada em/);
  });

  it("asks for the second unlock password too when two-password unlock is active", async () => {
    backend.gate = gate({ dual: true });
    await render(<UnlockPolicySection />); // popula o gate no store
    await flush();
    await cleanup();
    await render(<RecoveryPasswordSection />);
    await flush();
    await click(buttonByText("Configurar"));
    await flush();
    const [current, current2, newPassword, confirm] = modalPasswords();
    await typeInto(current, "senha-um-fictícia");
    await typeInto(current2, "senha-dois-fictícia");
    await typeInto(newPassword, "recuperacao-fictícia-1");
    await typeInto(confirm, "recuperacao-fictícia-1");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("set_recovery_password")[0][1]).toEqual({
      currentPassword: "senha-um-fictícia",
      currentPassword2: "senha-dois-fictícia",
      newRecoveryPassword: "recuperacao-fictícia-1",
    });
  });

  it("disables with re-authentication and reports backend errors clearly", async () => {
    backend.recoveryPassword = { enabled: true, created_at: "2026-02-01T10:00:00Z" };
    await render(<RecoveryPasswordSection />);
    await flush();
    await click(buttonByText("Desativar"));
    await flush();
    await typeInto(modalPasswords()[0], "senha-errada-1234");
    backend.error = "Senha incorreta.";
    await submit(document.querySelector("form"));
    await flush(5);
    expect(document.body.textContent).toMatch(/Senha incorreta/);

    backend.error = null;
    backend.recoveryPassword = { enabled: false, created_at: null };
    await typeInto(modalPasswords()[0], "senha-mestra-fictícia");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(calls("disable_recovery_password")).toHaveLength(2);
    expect(byTestId("recovery-password-section")?.textContent).toMatch(/Não configurada/);
  });

  it("never prints the typed passwords in the page text", async () => {
    await render(<RecoveryPasswordSection />);
    await flush();
    await click(buttonByText("Configurar"));
    await flush();
    const [current, newPassword, confirm] = modalPasswords();
    await typeInto(current, "SEGREDO-ATUAL-ABC");
    await typeInto(newPassword, "SEGREDO-NOVO-XYZ");
    await typeInto(confirm, "SEGREDO-DIFERENTE-123");
    await submit(document.querySelector("form"));
    expect(document.body.textContent).not.toContain("SEGREDO-ATUAL-ABC");
    expect(document.body.textContent).not.toContain("SEGREDO-NOVO-XYZ");
    expect(document.body.textContent).not.toContain("SEGREDO-DIFERENTE-123");
  });
});
