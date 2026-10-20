import { describe, expect, it } from "vitest";
import { parseStructuredError, translateBackendError } from "../backendErrors";
import { SUPPORTED_LOCALES, translate, type Locale } from "..";

const tFor = (locale: Locale) => (key: string, vars?: Record<string, string | number>) => translate(locale, key, vars);

describe("parseStructuredError", () => {
  it("parses the lockout code with seconds and failure count", () => {
    expect(parseStructuredError("E_LOCKED:15:1")).toEqual({ code: "locked", seconds: 15, failures: 1 });
    expect(parseStructuredError("E_LOCKED:14400:9")).toEqual({ code: "locked", seconds: 14400, failures: 9 });
  });

  it("parses the other structured codes and ignores ordinary messages", () => {
    expect(parseStructuredError("E_VAULT_OPEN_ELSEWHERE")).toEqual({ code: "vault_open_elsewhere" });
    expect(parseStructuredError("E_SECOND_PASSWORD_REQUIRED")).toEqual({ code: "second_password_required" });
    expect(parseStructuredError("Senha incorreta.")).toBeNull();
    expect(parseStructuredError("E_LOCKED:abc:1")).toBeNull();
    expect(parseStructuredError("prefixo E_LOCKED:15:1")).toBeNull();
  });
});

describe("translateBackendError — mensagens compreensíveis nos três idiomas", () => {
  it("shows the remaining wait for a lockout", () => {
    expect(translateBackendError(tFor("pt-BR"), "E_LOCKED:300:4")).toContain("5 min");
    expect(translateBackendError(tFor("en"), "E_LOCKED:3600:6")).toContain("1 h");
    expect(translateBackendError(tFor("es"), "E_LOCKED:15:1")).toContain("15 s");
  });

  it("explains that a vault is already open elsewhere", () => {
    for (const locale of SUPPORTED_LOCALES) {
      const message = translateBackendError(tFor(locale), "E_VAULT_OPEN_ELSEWHERE");
      expect(message).not.toBe("E_VAULT_OPEN_ELSEWHERE");
      expect(message.length).toBeGreaterThan(20);
    }
  });

  it("tells apart wrong password, wrong recovery password, corrupted data and missing configuration", () => {
    const t = tFor("pt-BR");
    const messages = [
      "Senha incorreta.",
      "Segunda senha de recuperação incorreta.",
      "Os dados da segunda senha de recuperação estão corrompidos.",
      "Os dados de proteção do cofre estão corrompidos ou usam um formato não suportado.",
      "Nenhuma segunda senha de recuperação foi configurada para este cofre.",
      "A segunda senha de recuperação deve ter pelo menos 8 caracteres.",
      "E_SECOND_PASSWORD_REQUIRED",
    ].map((raw) => translateBackendError(t, raw));
    expect(new Set(messages).size).toBe(messages.length);
    for (const message of messages) expect(message).not.toMatch(/^errors\./); // nenhuma chave sem tradução
  });

  it("a corrupted-data message does not blame the password", () => {
    expect(translateBackendError(tFor("pt-BR"), "Os dados de proteção do cofre estão corrompidos ou usam um formato não suportado.")).toMatch(/não indica senha incorreta/i);
  });

  it("every new backend message has a translation in every language", () => {
    const raws = [
      "O desbloqueio com duas senhas já está ativado.",
      "O desbloqueio com duas senhas não está ativado.",
      "A segunda senha precisa ser diferente da primeira.",
      "A segunda senha deve ter pelo menos 8 caracteres.",
      "A senha é longa demais.",
      "A senha de recuperação precisa ser diferente das senhas de desbloqueio.",
      "A data do último login não pode estar no futuro.",
      "A data do último login é inválida.",
    ];
    for (const locale of SUPPORTED_LOCALES) {
      for (const raw of raws) {
        const message = translateBackendError(tFor(locale), raw);
        expect(message).not.toMatch(/^errors\./);
        if (locale !== "pt-BR") expect(message).not.toBe(raw);
      }
    }
  });

  it("unknown technical messages pass through unchanged", () => {
    expect(translateBackendError(tFor("en"), "disk I/O error")).toBe("disk I/O error");
  });
});
