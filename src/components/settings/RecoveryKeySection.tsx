import { FormEvent, useCallback, useEffect, useState } from "react";
import { AlertTriangle, Check, Copy, KeyRound, Printer, RefreshCw, ShieldOff } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { RecoveryKitDialog } from "./RecoveryKitDialog";
import { clipboardCommands, recoveryKeyCommands, type RecoveryKeyStatus } from "../../lib/tauri";
import { useCopySecret } from "../../lib/useCopy";
import { useToastStore } from "../../store/useToastStore";
import { SecondPasswordField, useDualUnlock } from "../security/SecondPasswordField";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

type PendingAction = "generate" | "disable" | null;

export function RecoveryKeySection() {
  const { t, intlLocale } = useTranslation();
  const [status, setStatus] = useState<RecoveryKeyStatus | null>(null);
  // Fase 4 (SECURITY_AUDIT_PHASE_4.md): gerar/desativar a Recovery Key exige reautenticação —
  // a senha mestra é conferida de verdade no comando Rust, não é um "já confirmei" do frontend.
  const [pendingAction, setPendingAction] = useState<PendingAction>(null);
  const [reauthPassword, setReauthPassword] = useState("");
  const [reauthPassword2, setReauthPassword2] = useState("");
  const dual = useDualUnlock();
  const [reauthError, setReauthError] = useState<string | null>(null);
  const [reauthSubmitting, setReauthSubmitting] = useState(false);
  // A chave só existe em memória do frontend entre gerar e fechar este diálogo — nunca é
  // persistida (nem localStorage), e é descartada assim que o usuário confirma que guardou.
  const [freshKey, setFreshKey] = useState<string | null>(null);
  const [kitOpen, setKitOpen] = useState(false);
  // A Recovery Key é copiada pelo caminho de segredo (no Windows: fora do Histórico Win+V e da
  // sincronização em nuvem da área de transferência).
  const copySecret = useCopySecret();
  const push = useToastStore((s) => s.push);

  const refresh = useCallback(async () => {
    setStatus(await recoveryKeyCommands.status());
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function closeReauth() {
    setPendingAction(null);
    setReauthPassword("");
    setReauthPassword2("");
    setReauthError(null);
  }

  async function handleReauthSubmit(e: FormEvent) {
    e.preventDefault();
    if (!pendingAction) return;
    setReauthSubmitting(true);
    setReauthError(null);
    try {
      if (pendingAction === "generate") {
        const key = await recoveryKeyCommands.generate(reauthPassword, dual ? reauthPassword2 : undefined);
        setFreshKey(key);
      } else {
        await recoveryKeyCommands.disable(reauthPassword, dual ? reauthPassword2 : undefined);
        push(t("settings.recoveryKey.disabledToast"), "success");
      }
      closeReauth();
      await refresh();
    } catch (err) {
      setReauthError(translateBackendError(t, err));
    } finally {
      setReauthSubmitting(false);
    }
  }

  function handleDoneWithFreshKey() {
    // Descarta o valor do estado do React — depois disso, ninguém (nem o próprio app) consegue
    // mais mostrar esta chave de novo; só resta gerar uma nova.
    setFreshKey(null);
  }

  return (
    <div className="space-y-3 border-t border-[var(--color-border)] pt-4">
      <div className="flex items-center gap-2 text-sm font-medium">
        <KeyRound size={15} /> {t("settings.recoveryKey.title")}
      </div>
      <p className="text-xs text-[var(--color-text-muted)]">{t("settings.recoveryKey.description")}</p>

      {status?.enabled ? (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900">
          <Check size={15} className="shrink-0" />
          <span>
            {t("settings.recoveryKey.enabledLabel", {
              dateSuffix: status.created_at
                ? t("settings.recoveryKey.enabledDateSuffix", { date: new Date(status.created_at).toLocaleDateString(intlLocale) })
                : "",
            })}
          </span>
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          <AlertTriangle size={15} className="shrink-0" />
          <span>{t("settings.recoveryKey.notConfiguredLabel")}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" size="sm" onClick={() => setPendingAction("generate")}>
          <RefreshCw size={14} /> {status?.enabled ? t("settings.recoveryKey.generateNew") : t("settings.recoveryKey.generate")}
        </Button>
        {status?.enabled && (
          <Button variant="secondary" size="sm" onClick={() => setPendingAction("disable")}>
            <ShieldOff size={14} /> {t("settings.recoveryKey.disable")}
          </Button>
        )}
      </div>

      <Modal
        open={pendingAction !== null}
        onClose={closeReauth}
        title={
          pendingAction === "disable"
            ? t("settings.recoveryKey.modalTitleDisable")
            : status?.enabled
              ? t("settings.recoveryKey.modalTitleRegenerate")
              : t("settings.recoveryKey.modalTitleGenerate")
        }
        width="sm"
      >
        <form onSubmit={handleReauthSubmit} className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            {pendingAction === "disable"
              ? t("settings.recoveryKey.disableWarning")
              : status?.enabled
                ? t("settings.recoveryKey.regenerateWarning")
                : t("settings.recoveryKey.generateWarning")}
          </p>
          <p className="text-xs text-[var(--color-text-muted)]">{t("settings.recoveryKey.confirmPasswordHint")}</p>
          <div>
            <Label>{t("settings.recoveryKey.masterPasswordLabel")}</Label>
            <Input
              type="password"
              value={reauthPassword}
              onChange={(e) => setReauthPassword(e.target.value)}
              autoFocus
              disabled={reauthSubmitting}
            />
          </div>
          <SecondPasswordField value={reauthPassword2} onChange={setReauthPassword2} disabled={reauthSubmitting} />
          {reauthError && <p className="text-sm text-[var(--color-danger)]">{reauthError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={closeReauth} disabled={reauthSubmitting}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant={pendingAction === "disable" ? "danger" : "primary"} disabled={!reauthPassword || (dual && !reauthPassword2) || reauthSubmitting}>
              {reauthSubmitting ? t("common.verifying") : pendingAction === "disable" ? t("settings.recoveryKey.disableButton") : t("settings.recoveryKey.generateButton")}
            </Button>
          </div>
        </form>
      </Modal>

      <Modal open={!!freshKey} onClose={() => {}} title={t("settings.recoveryKey.yourKeyTitle")} width="sm">
        <div className="space-y-3">
          <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <p className="text-sm">{t("settings.recoveryKey.yourKeyWarning")}</p>
          </div>
          <p className="select-all rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-3 text-center font-mono text-base tracking-wider">
            {freshKey}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" size="sm" onClick={() => freshKey && copySecret(true, (secs) => clipboardCommands.copySecret(freshKey, secs), t("recovery.recoveryKeyLabel"))}>
              <Copy size={13} /> {t("common.copy")}
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setKitOpen(true)}>
              <Printer size={13} /> {t("settings.recoveryKey.printKit")}
            </Button>
          </div>
          <Button variant="primary" className="w-full" onClick={handleDoneWithFreshKey}>
            {t("settings.recoveryKey.doneSafe")}
          </Button>
        </div>
      </Modal>

      <RecoveryKitDialog open={kitOpen} onClose={() => setKitOpen(false)} recoveryKey={freshKey} />
    </div>
  );
}
