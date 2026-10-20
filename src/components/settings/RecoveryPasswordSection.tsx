import { FormEvent, useCallback, useEffect, useState } from "react";
import { AlertTriangle, Check, LifeBuoy, ShieldOff } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { PasswordStrengthMeter } from "../ui/PasswordStrengthMeter";
import { SecondPasswordField } from "../security/SecondPasswordField";
import { recoveryPasswordCommands, type RecoveryPasswordStatus } from "../../lib/tauri";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

type Mode = "set" | "disable" | null;

const MIN_LENGTH = 8;

/**
 * Configurações → Segurança: segunda senha de recuperação (opcional, desligada por padrão). É um
 * método de recuperação INDEPENDENTE do desbloqueio normal, da Recovery Key e das perguntas de
 * segurança: ativar, trocar ou desativar não afeta os outros. Operações sensíveis reautenticam as
 * credenciais atuais no backend.
 */
export function RecoveryPasswordSection() {
  const { t, intlLocale } = useTranslation();
  const [status, setStatus] = useState<RecoveryPasswordStatus | null>(null);
  const [mode, setMode] = useState<Mode>(null);
  const [current, setCurrent] = useState("");
  const [current2, setCurrent2] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const dual = useSecurityStore((s) => s.gate?.dual ?? false);
  const refreshGate = useSecurityStore((s) => s.refresh);
  const push = useToastStore((s) => s.push);

  const refresh = useCallback(async () => {
    try {
      setStatus(await recoveryPasswordCommands.status());
    } catch (err) {
      setStatus(null);
      setError(translateBackendError(t, err));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function close() {
    setMode(null);
    setCurrent("");
    setCurrent2("");
    setNewPassword("");
    setConfirm("");
    setError(null);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!current || (dual && !current2)) {
      setError(dual && current && !current2 ? t("errors.secondPasswordRequired") : t("security.reauthHint"));
      return;
    }
    if (mode === "set") {
      if (newPassword.length < MIN_LENGTH) {
        setError(t("errors.recoveryPwTooShort"));
        return;
      }
      if (newPassword !== confirm) {
        setError(t("security.recoveryPassword.mismatch"));
        return;
      }
    }
    setSubmitting(true);
    setError(null);
    try {
      if (mode === "set") {
        await recoveryPasswordCommands.set(current, newPassword, dual ? current2 : undefined);
        push(status?.enabled ? t("security.recoveryPassword.changedToast") : t("security.recoveryPassword.setToast"), "success");
      } else {
        await recoveryPasswordCommands.disable(current, dual ? current2 : undefined);
        push(t("security.recoveryPassword.disabledToast"), "success");
      }
      close();
      await refresh();
      await refreshGate();
    } catch (err) {
      setError(translateBackendError(t, err));
    } finally {
      setSubmitting(false);
    }
  }

  const enabled = status?.enabled ?? false;
  const title =
    mode === "disable"
      ? t("security.recoveryPassword.disableTitle")
      : enabled
        ? t("security.recoveryPassword.changeTitle")
        : t("security.recoveryPassword.setTitle");

  return (
    <div className="space-y-3 border-t border-[var(--color-border)] pt-4" data-testid="recovery-password-section">
      <div className="flex items-center gap-2 text-sm font-medium">
        <LifeBuoy size={15} /> {t("security.recoveryPassword.title")}
      </div>
      <p className="text-xs text-[var(--color-text-muted)]">{t("security.recoveryPassword.description")}</p>

      {enabled ? (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900">
          <Check size={15} className="shrink-0" />
          <span>
            {status?.created_at
              ? t("security.recoveryPassword.statusOn", { date: new Date(status.created_at).toLocaleDateString(intlLocale) })
              : t("security.recoveryPassword.statusOnNoDate")}
          </span>
        </div>
      ) : (
        <div className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-muted)]">
          <span>{t("security.recoveryPassword.statusOff")}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" size="sm" onClick={() => setMode("set")}>
          {enabled ? t("security.recoveryPassword.changeButton") : t("security.recoveryPassword.setButton")}
        </Button>
        {enabled && (
          <Button variant="secondary" size="sm" onClick={() => setMode("disable")}>
            <ShieldOff size={14} /> {t("security.recoveryPassword.disableButton")}
          </Button>
        )}
      </div>

      <Modal open={mode !== null} onClose={close} title={title} width="sm">
        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === "set" ? (
            <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900" role="alert">
              <AlertTriangle size={18} className="mt-0.5 shrink-0" />
              <p className="text-xs">{t("security.recoveryPassword.warning")}</p>
            </div>
          ) : (
            <p className="text-sm text-[var(--color-text-muted)]">{t("security.recoveryPassword.disableWarning")}</p>
          )}
          <p className="text-xs text-[var(--color-text-muted)]">{t("security.reauthHint")}</p>
          <div>
            <Label>{dual ? t("security.currentFirstPasswordLabel") : t("settings.security.currentPasswordLabel")}</Label>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus disabled={submitting} />
          </div>
          <SecondPasswordField value={current2} onChange={setCurrent2} disabled={submitting} />
          {mode === "set" && (
            <>
              <div>
                <Label>{t("security.recoveryPassword.newLabel")}</Label>
                <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" disabled={submitting} />
                <PasswordStrengthMeter password={newPassword} />
              </div>
              <div>
                <Label>{t("security.recoveryPassword.confirmLabel")}</Label>
                <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" disabled={submitting} />
              </div>
            </>
          )}
          {error && (
            <p role="alert" className="text-sm text-[var(--color-danger)]">
              {error}
            </p>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={close} disabled={submitting}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant={mode === "disable" ? "danger" : "primary"} disabled={submitting}>
              {submitting ? t("common.verifying") : t("security.recoveryPassword.submit")}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
