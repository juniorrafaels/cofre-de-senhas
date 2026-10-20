// Auxiliares de teste de componentes SEM dependências extras: `react-dom/client` + `act` do React.
// Cada arquivo de teste que renderiza componentes precisa do docblock `@vitest-environment jsdom`.
import { act, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// jsdom não implementa `matchMedia` (o store de configurações o usa para reagir ao tema do SO).
if (typeof window !== "undefined" && !window.matchMedia) {
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

const mounted: { root: Root; container: HTMLElement }[] = [];

export async function render(element: ReactElement) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  mounted.push({ root, container });
  await act(async () => {
    root.render(element);
  });
  return {
    container,
    rerender: async (next: ReactElement) => {
      await act(async () => {
        root.render(next);
      });
    },
  };
}

export async function cleanup() {
  for (const { root, container } of mounted.splice(0)) {
    await act(async () => {
      root.unmount();
    });
    container.remove();
  }
  document.body.innerHTML = "";
}

/** Deixa promessas pendentes (mocks assíncronos, setState) se resolverem dentro de `act`. */
export async function flush(times = 3) {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

export async function click(el: Element | null) {
  if (!el) throw new Error("elemento para clicar não encontrado");
  await act(async () => {
    (el as HTMLElement).click();
  });
}

/** Digita num input controlado do React (usa o setter nativo + evento `input`). */
export async function typeInto(el: Element | null, value: string) {
  if (!el) throw new Error("campo para digitar não encontrado");
  const input = el as HTMLInputElement | HTMLTextAreaElement;
  const proto = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")!.set!;
  await act(async () => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

export async function submit(form: Element | null) {
  if (!form) throw new Error("formulário não encontrado");
  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}

export function byTestId(testId: string, root: ParentNode = document.body): HTMLElement | null {
  return root.querySelector(`[data-testid="${testId}"]`);
}

export function buttonByText(text: string | RegExp, root: ParentNode = document.body): HTMLButtonElement | null {
  const buttons = Array.from(root.querySelectorAll("button"));
  return (
    (buttons.find((b) => (typeof text === "string" ? b.textContent?.trim() === text : text.test(b.textContent ?? ""))) as
      | HTMLButtonElement
      | undefined) ?? null
  );
}

export function inputsOfType(type: string, root: ParentNode = document.body): HTMLInputElement[] {
  return Array.from(root.querySelectorAll(`input[type="${type}"]`)) as HTMLInputElement[];
}
