// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buttonByText, byTestId, cleanup, click, flush, inputsOfType, render, submit, typeInto } from "../../test/dom";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));

import { RecoveryFlow } from "../vault/RecoveryFlow";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useVaultStore } from "../../store/useVaultStore";
import { useLocaleStore } from "../../i18n";

const backend = {
  questions: { count: 0, min_required_for_recovery: 3 },
  recoveryKey: { enabled: false, created_at: null as string | null },
  recoveryPassword: { enabled: true, created_at: "2026-01-01T00:00:00Z" as string | null },
  recoveryPasswordError: null as string | null,
};

beforeEach(() => {
  invoke.mockReset();
  backend.questions = { count: 0, min_required_for_recovery: 3 };
  backend.recoveryKey = { enabled: false, created_at: null };
  backend.recoveryPassword = { enabled: true, created_at: "2026-01-01T00:00:00Z" };
  backend.recoveryPasswordError = null;
  invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "security_questions_summary":
        return backend.questions;
      case "recovery_key_status":
        return backend.recoveryKey;
      case "recovery_password_status":
        return backend.recoveryPassword;
      case "unlock_with_recovery_password":
        if (backend.recoveryPasswordError) throw backend.recoveryPasswordError;
        return undefined;
      case "unlock_gate_status":
        return { initialized: true, unlocked: false, dual: true, throttle_enabled: false, locked: false, remaining_seconds: 0, failed_count: 0, open_elsewhere: false, recovery_password_enabled: true, protection_corrupt: false };
      default:
        return undefined;
    }
  });
  useSecurityStore.setState({ gate: null });
  useVaultStore.setState({ status: "locked" });
  useLocaleStore.getState().setLocale("pt-BR");
});

afterEach(async () => {
  await cleanup();
});

describe("RecoveryFlow — segunda senha de recuperação", () => {
  it("goes straight to the second recovery password when it is the only configured method", async () => {
    await render(<RecoveryFlow open onClose={() => {}} />);
    await flush(5);
    expect(document.body.textContent).toMatch(/Digite a segunda senha de recuperação/);
    expect(inputsOfType("password")).toHaveLength(1);
  });

  it("lists every available method when there is more than one", async () => {
    backend.recoveryKey = { enabled: true, created_at: "2026-01-01T00:00:00Z" };
    await render(<RecoveryFlow open onClose={() => {}} />);
    await flush(5);
    expect(buttonByText(/Recovery Key/i)).not.toBeNull();
    expect(buttonByText(/segunda senha de recuperação/i)).not.toBeNull();
    // Sem perguntas suficientes: esse método NÃO é oferecido.
    expect(buttonByText(/perguntas de segurança/i)).toBeNull();
  });

  it("reports the method as unavailable only when nothing is configured", async () => {
    backend.recoveryPassword = { enabled: false, created_at: null };
    await render(<RecoveryFlow open onClose={() => {}} />);
    await flush(5);
    expect(document.body.textContent).toMatch(/recuperação/i);
    expect(inputsOfType("password")).toHaveLength(0);
  });

  it("sends the password and moves on to resetting the master password on success", async () => {
    await render(<RecoveryFlow open onClose={() => {}} />);
    await flush(5);
    await typeInto(inputsOfType("password")[0], "recuperacao-ficticia-1");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(invoke).toHaveBeenCalledWith("unlock_with_recovery_password", { recoveryPassword: "recuperacao-ficticia-1" });
    expect(document.body.textContent).toMatch(/Identidade confirmada|identidade/i);
    // Com duas senhas ativas o usuário é avisado de que voltará a uma senha só.
    expect(document.body.textContent).toMatch(/volta a uma senha só/);
  });

  it("shows a comprehensible message for each kind of failure", async () => {
    const cases: [string, RegExp][] = [
      ["Segunda senha de recuperação incorreta.", /Segunda senha de recuperação incorreta/],
      ["Os dados da segunda senha de recuperação estão corrompidos.", /estão corrompidos/],
      ["A segunda senha de recuperação deve ter pelo menos 8 caracteres.", /pelo menos 8 caracteres/],
      ["Nenhuma segunda senha de recuperação foi configurada para este cofre.", /Nenhuma segunda senha de recuperação/],
      ["E_LOCKED:30:2", /Tente novamente em 30 s/],
      ["E_VAULT_OPEN_ELSEWHERE", /já existe um cofre aberto/i],
    ];
    for (const [raw, expected] of cases) {
      backend.recoveryPasswordError = raw;
      await render(<RecoveryFlow open onClose={() => {}} />);
      await flush(5);
      await typeInto(inputsOfType("password")[0], "recuperacao-ficticia-1");
      await submit(document.querySelector("form"));
      await flush(5);
      expect(byTestId("recovery-password-error")?.textContent ?? "", raw).toMatch(expected);
      await cleanup();
    }
  });

  it("does not leave the typed recovery password around after a failed attempt is dismissed", async () => {
    backend.recoveryPasswordError = "Segunda senha de recuperação incorreta.";
    await render(<RecoveryFlow open onClose={() => {}} />);
    await flush(5);
    await typeInto(inputsOfType("password")[0], "recuperacao-ficticia-1");
    await submit(document.querySelector("form"));
    await flush(5);
    // O texto digitado nunca aparece em nenhuma mensagem de erro.
    expect(document.body.textContent).not.toContain("recuperacao-ficticia-1");
    await click(buttonByText("Confirmar"));
  });
});
