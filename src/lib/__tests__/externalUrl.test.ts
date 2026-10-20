// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const openUrlMock = vi.fn();
vi.mock("@tauri-apps/plugin-opener", () => ({ openUrl: (url: string) => openUrlMock(url) }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

// jsdom não implementa `matchMedia` (usado pelos stores carregados via i18n).
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

import { isAllowedExternalUrl, normalizeExternalUrl, openLoginUrl } from "../tauri";
// `?raw` (Vite) lê o arquivo como texto sem precisar de @types/node.
import casesJson from "../../../test-fixtures/external-urls.json?raw";

// Os mesmos casos são exercitados pelo validador Rust (src-tauri/src/validate.rs): os dois lados
// precisam concordar, senão uma URL poderia ser salva e não abrir (ou o contrário).
const cases = JSON.parse(casesJson) as {
  accept: string[];
  reject: string[];
};

describe("isAllowedExternalUrl (casos compartilhados com o backend Rust)", () => {
  it("tem casos de aceitação e de rejeição", () => {
    expect(cases.accept.length).toBeGreaterThan(10);
    expect(cases.reject.length).toBeGreaterThan(30);
  });

  it.each(cases.accept)("aceita %j", (url) => {
    expect(isAllowedExternalUrl(url)).toBe(true);
  });

  it.each(cases.reject)("rejeita %j", (url) => {
    expect(isAllowedExternalUrl(url)).toBe(false);
  });

  it("rejeita vazio", () => {
    expect(isAllowedExternalUrl("")).toBe(false);
  });
});

describe("normalizeExternalUrl", () => {
  it("só coloca o esquema em minúsculas (o plugin opener compara a string crua, sensível a maiúsculas)", () => {
    expect(normalizeExternalUrl("HTTPS://Example.COM/Path?Q=1")).toBe("https://Example.COM/Path?Q=1");
    expect(normalizeExternalUrl("HtTp://localhost:1420")).toBe("http://localhost:1420");
    expect(normalizeExternalUrl("https://example.com")).toBe("https://example.com");
  });
});

describe("openLoginUrl", () => {
  beforeEach(() => openUrlMock.mockReset());

  it("abre https pelo plugin", async () => {
    await openLoginUrl("https://example.com");
    expect(openUrlMock).toHaveBeenCalledWith("https://example.com");
  });

  it("entrega ao plugin o esquema em minúsculas (URL antiga salva com HTTPS://)", async () => {
    await openLoginUrl("HTTPS://EXAMPLE.COM/a");
    expect(openUrlMock).toHaveBeenCalledWith("https://EXAMPLE.COM/a");
  });

  it("não chama o plugin para esquemas perigosos nem para URLs ambíguas e lança erro", async () => {
    for (const bad of ["javascript:alert(1)", "file:///C:/x", "https://good.com\\@evil.com", "https://evil.com@good.com/", "https://example.com/\u202eevil"]) {
      await expect(openLoginUrl(bad)).rejects.toThrow();
    }
    expect(openUrlMock).not.toHaveBeenCalled();
  });

  it("ignora URL vazia sem abrir nada", async () => {
    await openLoginUrl("");
    expect(openUrlMock).not.toHaveBeenCalled();
  });
});
