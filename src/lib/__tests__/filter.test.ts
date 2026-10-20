import { describe, expect, it } from "vitest";
import { matchesSearch, sortAccounts } from "../filter";
import type { AccountWithRelations } from "../../types";

// Dados fictícios. A lista chega ao frontend já descriptografada pelo Rust (cofre aberto), então a
// pesquisa continua sendo uma busca parcial em memória sobre os metadados.
function account(overrides: Partial<AccountWithRelations>): AccountWithRelations {
  return {
    id: 1,
    name: "conta",
    platform_id: null,
    category: null,
    username: null,
    email: null,
    has_password: false,
    login_url: null,
    website_url: null,
    favorite: 0,
    avatar_image_id: null,
    status: "active",
    deleted_at: null,
    two_factor_enabled: 0,
    two_factor_method: null,
    created_at: "2024-01-01",
    updated_at: "2024-01-01",
    unreadable_fields: [],
    platform: null,
    tags: [],
    projects: [],
    ...overrides,
  } as AccountWithRelations;
}

describe("matchesSearch (busca parcial sobre metadados descriptografados)", () => {
  const acc = account({ name: "Loja Exemplo", username: "audit-user-7391", email: "audit-email-7391@example.invalid", category: "Compras" });

  it("encontra por trecho do nome, usuário, e-mail e categoria, sem diferenciar maiúsculas", () => {
    expect(matchesSearch(acc, "exemplo")).toBe(true);
    expect(matchesSearch(acc, "USER-73")).toBe(true);
    expect(matchesSearch(acc, "7391@example")).toBe(true);
    expect(matchesSearch(acc, "compr")).toBe(true);
  });

  it("não encontra o que não existe e aceita busca vazia", () => {
    expect(matchesSearch(acc, "inexistente-xyz")).toBe(false);
    expect(matchesSearch(acc, "   ")).toBe(true);
  });

  it("campos ilegíveis (null) não quebram a busca", () => {
    const broken = account({ name: "[nome ilegível #3]", username: null, unreadable_fields: ["name", "username"] });
    expect(matchesSearch(broken, "ilegível")).toBe(true);
    expect(matchesSearch(broken, "audit-user")).toBe(false);
  });
});

describe("sortAccounts por nome", () => {
  it("ordena asc/desc pelo nome", () => {
    const list = [account({ id: 1, name: "banco" }), account({ id: 2, name: "alfa" }), account({ id: 3, name: "Zeta" })];
    expect(sortAccounts(list, "name", "asc").map((a) => a.name)).toEqual(["Zeta", "alfa", "banco"]);
    expect(sortAccounts(list, "name", "desc").map((a) => a.name)).toEqual(["banco", "alfa", "Zeta"]);
  });
});
