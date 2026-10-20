import { describe, expect, it } from "vitest";
import { translate, SUPPORTED_LOCALES } from "..";
import { translateBackendError } from "../backendErrors";
// `?raw` (Vite) lê o fonte Rust como texto sem precisar de @types/node.
import validateRs from "../../../src-tauri/src/validate.rs?raw";
import accountsRs from "../../../src-tauri/src/commands/accounts.rs?raw";
import platformsRs from "../../../src-tauri/src/commands/platforms.rs?raw";

// Mensagens EXATAS devolvidas por `validate::http_url_optional` (o backend Rust é monolíngue). O
// teste "contrato" abaixo confere que o texto continua igual no Rust; se mudar lá, falha aqui.
const TAIL =
  "deve ser um endereço completo começando com https:// (ou http://), sem espaços, barras invertidas, usuário/senha ou caracteres invisíveis.";
const LOGIN = `A URL de login ${TAIL}`;
const WEBSITE = `A URL do site ${TAIL}`;

describe("mensagens de URL do backend", () => {
  it("contrato: validate.rs ainda monta exatamente este texto", () => {
    expect(validateRs).toContain(`{field} ${TAIL}`);
    const commands = accountsRs + platformsRs;
    expect(commands).toContain('"A URL de login"');
    expect(commands).toContain('"A URL do site"');
  });

  for (const locale of SUPPORTED_LOCALES) {
    const t = (key: string, vars?: Record<string, string | number>) => translate(locale, key, vars);

    it(`"${locale}": traduz as duas mensagens para o idioma ativo`, () => {
      const login = translateBackendError(t, LOGIN);
      const website = translateBackendError(t, WEBSITE);
      expect(login).toBe(translate(locale, "errors.invalidLoginUrl"));
      expect(website).toBe(translate(locale, "errors.invalidWebsiteUrl"));
      if (locale !== "pt-BR") {
        // Nada de texto fixo em português nas interfaces em inglês e espanhol.
        expect(login).not.toBe(LOGIN);
        expect(website).not.toBe(WEBSITE);
        expect(login).not.toMatch(/endereço completo|usuário\/senha/);
      }
    });

    it(`"${locale}": a dica de URL inválida existe e está traduzida`, () => {
      const hint = translate(locale, "errors.urlInvalidHint");
      expect(hint).not.toBe("errors.urlInvalidHint");
      expect(hint).toContain("https://");
    });
  }

  it("mensagens desconhecidas continuam passando sem tradução (comportamento existente)", () => {
    const t = (key: string) => translate("en", key);
    expect(translateBackendError(t, "Erro técnico qualquer")).toBe("Erro técnico qualquer");
  });
});
