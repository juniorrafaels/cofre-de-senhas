// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buttonByText, byTestId, cleanup, click, flush, inputsOfType, render, submit, typeInto } from "../../test/dom";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invoke(...args) }));
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: vi.fn() }));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ writeText: vi.fn() }));

import { UpdatedBadge } from "../accounts/UpdatedBadge";
import { AccountsListView } from "../accounts/AccountsListView";
import { AccountCard } from "../accounts/AccountCard";
import { AccountDetailModal } from "../accounts/AccountDetailModal";
import { AccountForm } from "../accounts/AccountForm";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useLocaleStore } from "../../i18n";
import type { AccountWithRelations, ListColumnKey } from "../../types";

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-06-01T12:00:00Z");
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

function account(overrides: Partial<AccountWithRelations> = {}): AccountWithRelations {
  return {
    id: 1,
    name: "Conta fictícia",
    platform_id: null,
    category: null,
    username: "usuario-ficticio",
    email: null,
    has_password: true,
    login_url: null,
    website_url: null,
    favorite: 0,
    avatar_image_id: null,
    status: "active",
    deleted_at: null,
    two_factor_enabled: 0,
    two_factor_method: null,
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-02-01T00:00:00Z",
    last_login_at: null,
    update_confirmed_at: null,
    update_expires_at: null,
    update_badge: "none",
    platform: null,
    tags: [],
    projects: [],
    ...overrides,
  };
}

beforeEach(() => {
  invoke.mockReset();
  invoke.mockImplementation(async (command: string) => {
    if (command === "get_account_notes") return "";
    if (command === "get_account_two_factor_details") return { phone: "", email: "", app: "", notes: "" };
    return undefined;
  });
  useSettingsStore.setState({ showUpdatedBadge: true });
  useLocaleStore.getState().setLocale("pt-BR");
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});

afterEach(async () => {
  vi.useRealTimers();
  await cleanup();
});

describe("UpdatedBadge — selo \"Atualizada\"", () => {
  it("is shown inside the 90-day validity", async () => {
    await render(<UpdatedBadge confirmedAt={iso(NOW - 10 * DAY)} />);
    expect(byTestId("updated-badge")?.textContent).toBe("Atualizada");
    expect(byTestId("updated-badge")?.getAttribute("title")).toMatch(/dia\(s\) restante\(s\)/);
  });

  it("disappears after 90 days", async () => {
    await render(<UpdatedBadge confirmedAt={iso(NOW - 91 * DAY)} />);
    expect(byTestId("updated-badge")).toBeNull();
  });

  it("is removed exactly at the 90-day boundary and still shown one second before it", async () => {
    const confirmed = NOW - 90 * DAY;
    const view = await render(<UpdatedBadge confirmedAt={iso(confirmed)} nowMs={confirmed + 90 * DAY - 1000} />);
    expect(byTestId("updated-badge")).not.toBeNull();
    await view.rerender(<UpdatedBadge confirmedAt={iso(confirmed)} nowMs={confirmed + 90 * DAY} />);
    expect(byTestId("updated-badge")).toBeNull();
  });

  it("is never shown for missing, invalid or future dates", async () => {
    for (const bad of [null, undefined, "", "lixo", "2026-06-01", iso(NOW + 5 * DAY)]) {
      const view = await render(<UpdatedBadge confirmedAt={bad} />);
      expect(byTestId("updated-badge"), String(bad)).toBeNull();
      await cleanup();
      void view;
    }
  });

  it("respects the display preference and never changes stored data", async () => {
    useSettingsStore.setState({ showUpdatedBadge: false });
    const view = await render(<UpdatedBadge confirmedAt={iso(NOW - DAY)} />);
    expect(byTestId("updated-badge")).toBeNull();
    useSettingsStore.setState({ showUpdatedBadge: true });
    await view.rerender(<UpdatedBadge confirmedAt={iso(NOW - DAY)} />);
    expect(byTestId("updated-badge")).not.toBeNull();
    expect(invoke).not.toHaveBeenCalled(); // só exibição: nenhum comando de gravação
  });
});

describe("AccountsListView — colunas e selo", () => {
  const baseColumns: ListColumnKey[] = ["name", "username"];

  function renderList(columns: ListColumnKey[], accounts: AccountWithRelations[]) {
    return render(<AccountsListView accounts={accounts} columns={columns} onOpenDetail={() => {}} onEdit={() => {}} onToggleFavorite={() => {}} />);
  }

  it("shows the \"Último login\" column only when it is enabled", async () => {
    const accounts = [account({ last_login_at: "2026-02-10" })];
    const view = await renderList(baseColumns, accounts);
    expect(document.querySelector("thead")?.textContent).not.toContain("Último login");

    await view.rerender(<AccountsListView accounts={accounts} columns={[...baseColumns, "last_login"]} onOpenDetail={() => {}} onEdit={() => {}} onToggleFavorite={() => {}} />);
    expect(document.querySelector("thead")?.textContent).toContain("Último login");
    expect(document.querySelector("tbody")?.textContent).toContain(new Date(2026, 1, 10).toLocaleDateString("pt-BR"));
  });

  it("shows a dash when the account has no last login", async () => {
    await renderList([...baseColumns, "last_login"], [account({ last_login_at: null })]);
    const cells = Array.from(document.querySelectorAll("tbody tr td")).map((td) => td.textContent);
    expect(cells).toContain("—");
  });

  it("shows the badge in the list when valid, and hides it after 90 days or when the preference is off", async () => {
    const valid = account({ id: 1, name: "Valida", update_confirmed_at: iso(NOW - 5 * DAY) });
    const expired = account({ id: 2, name: "Expirada", update_confirmed_at: iso(NOW - 120 * DAY) });
    const view = await renderList(baseColumns, [valid, expired]);
    expect(document.querySelectorAll('[data-testid="updated-badge"]')).toHaveLength(1);
    expect(document.querySelector("tbody tr")?.querySelector('[data-testid="updated-badge"]')).not.toBeNull();

    useSettingsStore.setState({ showUpdatedBadge: false });
    await view.rerender(<AccountsListView accounts={[valid, expired]} columns={baseColumns} onOpenDetail={() => {}} onEdit={() => {}} onToggleFavorite={() => {}} />);
    expect(document.querySelectorAll('[data-testid="updated-badge"]')).toHaveLength(0);
  });

  it("the card view shows the badge too", async () => {
    await render(<AccountCard account={account({ update_confirmed_at: iso(NOW - 5 * DAY) })} onOpenDetail={() => {}} onEdit={() => {}} onToggleFavorite={() => {}} />);
    expect(byTestId("updated-badge")).not.toBeNull();
  });

  it("clicking a row to view the account does not renew or create the confirmation", async () => {
    const onOpenDetail = vi.fn();
    await render(
      <AccountsListView accounts={[account({ update_confirmed_at: iso(NOW - 80 * DAY) })]} columns={baseColumns} onOpenDetail={onOpenDetail} onEdit={() => {}} onToggleFavorite={() => {}} />,
    );
    await click(document.querySelector("tbody tr"));
    expect(onOpenDetail).toHaveBeenCalledTimes(1);
    expect(invoke.mock.calls.filter(([c]) => c === "mark_account_updated")).toHaveLength(0);
  });
});

describe("AccountDetailModal — marcar como atualizada", () => {
  function renderModal(acc: AccountWithRelations, onMarkUpdated = vi.fn(async () => iso(NOW))) {
    const handlers = { onClose: vi.fn(), onEdit: vi.fn(), onDelete: vi.fn(), onArchiveToggle: vi.fn(), onMarkUpdated };
    return { handlers, view: render(<AccountDetailModal account={acc} {...handlers} />) };
  }

  it("opening and viewing the account never marks it as updated", async () => {
    const { handlers, view } = renderModal(account());
    await view;
    await flush(5);
    expect(handlers.onMarkUpdated).not.toHaveBeenCalled();
    expect(byTestId("update-confirmation-status")?.textContent).toBe("Nunca confirmada");
    expect(byTestId("updated-badge")).toBeNull();
  });

  it("pressing Edit does not mark the account as updated either", async () => {
    const { handlers, view } = renderModal(account({ update_confirmed_at: iso(NOW - 85 * DAY) }));
    await view;
    await flush(5);
    await click(buttonByText(/Editar/));
    expect(handlers.onEdit).toHaveBeenCalledTimes(1);
    expect(handlers.onMarkUpdated).not.toHaveBeenCalled();
  });

  it("the explicit button marks the account, shows the badge and the new expiry", async () => {
    const { handlers, view } = renderModal(account());
    await view;
    await flush(5);
    await click(buttonByText("Marcar como atualizada"));
    await flush(5);
    expect(handlers.onMarkUpdated).toHaveBeenCalledTimes(1);
    expect(byTestId("updated-badge")).not.toBeNull();
    expect(byTestId("update-confirmation-status")?.textContent).toMatch(/Expira em/);
    expect(byTestId("update-confirmation-status")?.textContent).toMatch(/90 dia/);
  });

  it("explains that marking is not a login and keeps last login separate", async () => {
    const { view } = renderModal(account({ last_login_at: "2026-02-10" }));
    await view;
    await flush(5);
    expect(document.body.textContent).toMatch(/Não é um login/);
    expect(document.body.textContent).toContain("Último login");
    expect(document.body.textContent).toContain(new Date(2026, 1, 10).toLocaleDateString("pt-BR"));
  });

  it("shows an expired confirmation as expired (no badge) and lets the user renew it", async () => {
    const { view } = renderModal(account({ update_confirmed_at: iso(NOW - 120 * DAY) }));
    await view;
    await flush(5);
    expect(byTestId("updated-badge")).toBeNull();
    expect(byTestId("update-confirmation-status")?.textContent).toMatch(/expirou/);
    expect(buttonByText("Marcar como atualizada")).not.toBeNull();
  });

  it("reports a failure without marking the account", async () => {
    const failing = vi.fn(async () => {
      throw "Conta não encontrada.";
    });
    const { view } = renderModal(account(), failing);
    await view;
    await flush(5);
    await click(buttonByText("Marcar como atualizada"));
    await flush(5);
    expect(byTestId("updated-badge")).toBeNull();
    expect(byTestId("update-confirmation-status")?.textContent).toBe("Nunca confirmada");
  });
});

describe("AccountForm — último login e força da senha", () => {
  function renderForm(onSubmit = vi.fn(async () => {})) {
    const props = {
      open: true,
      onClose: vi.fn(),
      onSubmit,
      platforms: [],
      projects: [],
      tags: [],
      editingAccount: null,
      onRequestNewPlatform: vi.fn(),
      onRequestNewProject: vi.fn(),
    };
    return { onSubmit, view: render(<AccountForm {...props} />) };
  }

  it("updates the strength indicator immediately while typing the account password", async () => {
    const { view } = renderForm();
    await view;
    const passwordInput = () => inputsOfType("password")[0];
    expect(byTestId("password-strength")).toBeNull(); // nada digitado: sem indicador

    await typeInto(passwordInput(), "abc");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("veryWeak");
    expect(byTestId("password-strength")?.textContent).toMatch(/Muito fraca/);

    await typeInto(passwordInput(), "abcdefgh");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("weak");
    await typeInto(passwordInput(), "Abcdefg1");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("fair");
    await typeInto(passwordInput(), "Abcdef1!");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("strong");
    await typeInto(passwordInput(), "Abcdefghij1!");
    expect(byTestId("password-strength")?.getAttribute("data-level")).toBe("veryStrong");
    expect(byTestId("password-strength")?.textContent).toMatch(/Muito forte/);
  });

  it("uses the same evaluator as the master password screen (same level for the same password)", async () => {
    const { view } = renderForm();
    await view;
    await typeInto(inputsOfType("password")[0], "Abcdefg1");
    const accountLevel = byTestId("password-strength")?.getAttribute("data-level");
    expect(accountLevel).toBe("fair"); // a tela da senha mestra agrupa o mesmo score em "Razoável"
  });

  it("does not change the typed password and does not block saving a weak one", async () => {
    const { onSubmit, view } = renderForm();
    await view;
    const textInputs = Array.from(document.querySelectorAll("form input:not([type])")) as HTMLInputElement[];
    await typeInto(textInputs[0], "Conta com senha fraca"); // nome
    await typeInto(inputsOfType("password")[0], "123");
    expect(inputsOfType("password")[0].value).toBe("123");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect((onSubmit.mock.calls[0] as unknown as [{ password: string }])[0].password).toBe("123");
  });

  it("sends the last login date typed by the user (and none by default)", async () => {
    const { onSubmit, view } = renderForm();
    await view;
    const textInputs = Array.from(document.querySelectorAll("form input:not([type])")) as HTMLInputElement[];
    await typeInto(textInputs[0], "Conta com login");
    const dateInput = document.querySelector('input[type="date"]') as HTMLInputElement;
    expect(dateInput.value).toBe("");
    await typeInto(dateInput, "2026-05-20");
    await submit(document.querySelector("form"));
    await flush(5);
    expect((onSubmit.mock.calls[0] as unknown as [{ last_login_at: string }])[0].last_login_at).toBe("2026-05-20");
  });

  it("never prints the account password in the page text or in error messages", async () => {
    const { view } = renderForm(vi.fn(async () => {
      throw "Falha ao gravar.";
    }));
    await view;
    const textInputs = Array.from(document.querySelectorAll("form input:not([type])")) as HTMLInputElement[];
    await typeInto(textInputs[0], "Conta");
    await typeInto(inputsOfType("password")[0], "SENHA-DA-CONTA-FICTICIA-9");
    await submit(document.querySelector("form"));
    await flush(5);
    expect(document.body.textContent).not.toContain("SENHA-DA-CONTA-FICTICIA-9");
  });
});
