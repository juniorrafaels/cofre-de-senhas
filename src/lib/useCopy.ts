import { clipboardCommands } from "./tauri";
import { useSettingsStore } from "../store/useSettingsStore";
import { useToastStore } from "../store/useToastStore";
import { useTranslation } from "../i18n";
import { translateBackendError } from "../i18n/backendErrors";

export function useCopy() {
  const clipboardClearEnabled = useSettingsStore((s) => s.clipboardClearEnabled);
  const clipboardClearSeconds = useSettingsStore((s) => s.clipboardClearSeconds);
  const push = useToastStore((s) => s.push);
  const { t } = useTranslation();

  return async (text: string | null | undefined, label: string) => {
    if (!text) {
      push(t("common.nothingToCopy", { label: label.toLowerCase() }), "error");
      return;
    }
    try {
      await clipboardCommands.copy(text, clipboardClearEnabled ? clipboardClearSeconds : undefined);
      push(
        clipboardClearEnabled
          ? t("common.copiedWithClear", { label, seconds: clipboardClearSeconds })
          : t("common.copied", { label }),
        "success",
      );
    } catch (err) {
      push(t("common.copyFailed", { error: translateBackendError(t, err) }), "error");
    }
  };
}

/// Copia um segredo sem passar o plaintext pelo frontend: o Rust busca por ID, decifra e escreve
/// direto na área de transferência. Fase 4 (SECURITY_AUDIT_PHASE_4.md): recebe a própria chamada
/// específica (`() => accountSecretCommands.copyPassword(id, seconds)`, etc.) em vez de um
/// ciphertext — não existe mais um `copy_secret_to_clipboard(ciphertext)` genérico para envolver
/// aqui.
export function useCopySecret() {
  const clipboardClearEnabled = useSettingsStore((s) => s.clipboardClearEnabled);
  const clipboardClearSeconds = useSettingsStore((s) => s.clipboardClearSeconds);
  const push = useToastStore((s) => s.push);
  const { t } = useTranslation();

  return async (hasValue: boolean, copyFn: (clearAfterSeconds?: number) => Promise<void>, label: string) => {
    if (!hasValue) {
      push(t("common.nothingToCopy", { label: label.toLowerCase() }), "error");
      return;
    }
    try {
      await copyFn(clipboardClearEnabled ? clipboardClearSeconds : undefined);
      push(
        clipboardClearEnabled
          ? t("common.copiedWithClear", { label, seconds: clipboardClearSeconds })
          : t("common.copied", { label }),
        "success",
      );
    } catch (err) {
      push(t("common.copyFailed", { error: translateBackendError(t, err) }), "error");
    }
  };
}
