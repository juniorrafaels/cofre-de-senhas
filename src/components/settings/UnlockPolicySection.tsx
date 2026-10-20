import { FormEvent, useEffect, useState } from "react";
import { AlertTriangle, Check, KeyRound, ShieldOff, Timer } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { PasswordStrengthMeter } from "../ui/PasswordStrengthMeter";
import { SecondPasswordField } from "../security/SecondPasswordField";
import { unlockPolicyCommands } from "../../lib/tauri";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

type Mode = "enable-dual" | "change-second" | "disable-dual" | "throttle-on" | "throttle-off" | null;

const MIN_SECOND_LENGTH = 8;

/**
 * Configurações → Segurança: (1) desbloqueio com duas senhas e (2) bloqueio progressivo por
 * tentativas incorretas. As duas opções são independentes entre si e DESLIGADAS por padrão. Toda
 * alteração reautentica as credenciais atuais no backend e a exigência de duas senhas é aplicada
 * lá — esta tela só coleta os dados e explica os riscos ANTES de ativar.
 */
export function UnlockPolicySection() {
  const { t } = useTranslation();
  const gate = useSecurityStore((s) => s.gate);
  const refreshGate = useSecurityStore((s) => s.refresh);
  const push = useToastStore((s) => s.push);

  const [mode, setMode] = useState<Mode>(null);
  const [current, setCurrent] = useState("");
  const [current2, setCurrent2] = useState("");
  const [newSecond, setNewSecond] = useState("");
  const [confirmSecond, setConfirmSecond] = useState("");
  const [understood, setUnderstood] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    refreshGate();
  }, [refreshGate]);

  const dual = gate?.dual ?? false;
  const throttleOn = gate?.throttle_enabled ?? false;

  function close() {
    setMode(null);
    setCurrent("");
    setCurrent2("");
    setNewSecond("");
    setConfirmSecond("");
    setUnderstood(false);
    setError(null);
  }

  const needsNewSecond = mode === "enable-dual" || mode === "change-second";
  // No modo dual, "desativar" e "trocar" pedem as DUAS senhas atuais; ativar (cofre de uma senha) só a atual.
  const needsCurrent2Here = mode === "disable-dual" || mode === "change-second";
  const throttleNeedsCurrent2 = (mode === "throttle-on" || mode === "throttle-off") && dual;

  function validate(): string | null {
    if (!current) return t("security.reauthHint");
    if ((needsCurrent2Here || throttleNeedsCurrent2) && !current2) return t("errors.secondPasswordRequired");
    if (needsNewSecond) {
      if (newSecond.length < MIN_SECOND_LENGTH) return t("errors.secondTooShort");
      if (newSecond !== confirmSecond) return t("security.dual.mismatch");
      if (newSecond === current) return t("errors.secondSameAsFirst");
      if (mode === "enable-dual" && !understood) return t("security.dual.mustAcknowledge");
    }
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const problem = validate();
    if (problem) {
      setError(problem);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      switch (mode) {
        case "enable-dual":
          await unlockPolicyCommands.enableDual(current, newSecond);
          push(t("security.dual.enabledToast"), "success");
          break;
        case "change-second":
          await unlockPolicyCommands.changeSecond(current, current2, newSecond);
          push(t("security.dual.changedToast"), "success");
          break;
        case "disable-dual":
          await unlockPolicyCommands.disableDual(current, current2);
          push(t("security.dual.disabledToast"), "success");
          break;
        case "throttle-on":
          await unlockPolicyCommands.setThrottle(true, current, dual ? current2 : undefined);
          push(t("security.throttle.enabledToast"), "success");
          break;
        case "throttle-off":
          await unlockPolicyCommands.setThrottle(false, current, dual ? current2 : undefined);
          push(t("security.throttle.disabledToast"), "success");
          break;
      }
      close();
      await refreshGate();
    } catch (err) {
      setError(translateBackendError(t, err));
      await refreshGate();
    } finally {
      setSubmitting(false);
    }
  }

  const title =
    mode === "enable-dual"
      ? t("security.dual.enableTitle")
      : mode === "change-second"
        ? t("security.dual.changeSecondTitle")
        : mode === "disable-dual"
          ? t("security.dual.disableTitle")
          : mode === "throttle-on"
            ? t("security.throttle.enableTitle")
            : t("security.throttle.disableTitle");

  return (
    <div className="space-y-5 border-t border-[var(--color-border)] pt-4">
      {/* ---- Duas senhas ---- */}
      <div className="space-y-3" data-testid="dual-section">
        <div className="flex items-center gap-2 text-sm font-medium">
          <KeyRound size={15} /> {t("security.dual.title")}
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">{t("security.dual.description")}</p>
        <div
          className={
            dual
              ? "flex items-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900"
              : "flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-muted)]"
          }
        >
          {dual && <Check size={15} className="shrink-0" />}
          <span>{dual ? t("security.dual.statusOn") : t("security.dual.statusOff")}</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {dual ? (
            <>
              <Button variant="secondary" size="sm" onClick={() => setMode("change-second")}>
                {t("security.dual.changeSecondButton")}
              </Button>
              <Button variant="secondary" size="sm" onClick={() => setMode("disable-dual")}>
                <ShieldOff size={14} /> {t("security.dual.disableButton")}
              </Button>
            </>
          ) : (
            <Button variant="secondary" size="sm" onClick={() => setMode("enable-dual")}>
              {t("security.dual.enableButton")}
            </Button>
          )}
        </div>
      </div>

      {/* ---- Bloqueio progressivo ---- */}
      <div className="space-y-3 border-t border-[var(--color-border)] pt-4" data-testid="throttle-section">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Timer size={15} /> {t("security.throttle.title")}
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">{t("security.throttle.description")}</p>
        <p className="text-xs text-[var(--color-text-muted)]">{t("security.throttle.table")}</p>
        <p className="text-xs text-[var(--color-text-muted)]">{t("security.throttle.limits")}</p>
        <p className="text-xs text-[var(--color-text-muted)]">{t("security.throttle.recoveryNote")}</p>
        <div
          className={
            throttleOn
              ? "flex items-center gap-2 rounded-lg border border-emerald-300 bg-emerald-50 px-3 py-2 text-sm text-emerald-900"
              : "flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-muted)]"
          }
        >
          {throttleOn && <Check size={15} className="shrink-0" />}
          <span>{throttleOn ? t("security.throttle.statusOn") : t("security.throttle.statusOff")}</span>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setMode(throttleOn ? "throttle-off" : "throttle-on")}>
          {throttleOn ? t("security.throttle.disableButton") : t("security.throttle.enableButton")}
        </Button>
      </div>

      <Modal open={mode !== null} onClose={close} title={title} width="sm">
        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === "enable-dual" && (
            <div className="space-y-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900" role="alert">
              <p className="flex items-center gap-2 text-sm font-medium">
                <AlertTriangle size={16} className="shrink-0" /> {t("security.dual.riskTitle")}
              </p>
              <ul className="ml-5 list-disc space-y-1 text-xs">
                <li>{t("security.dual.risk1")}</li>
                <li>{t("security.dual.risk2")}</li>
                <li>{t("security.dual.risk3")}</li>
                <li>{t("security.dual.risk4")}</li>
              </ul>
              <label className="flex items-start gap-2 text-xs font-medium">
                <input type="checkbox" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} className="mt-0.5 h-4 w-4" />
                {t("security.dual.understood")}
              </label>
            </div>
          )}
          {mode === "disable-dual" && <p className="text-sm text-[var(--color-text-muted)]">{t("security.dual.disableWarning")}</p>}
          <p className="text-xs text-[var(--color-text-muted)]">{t("security.reauthHint")}</p>

          <div>
            <Label>{mode === "enable-dual" || needsCurrent2Here || throttleNeedsCurrent2 ? t("security.currentFirstPasswordLabel") : t("settings.security.currentPasswordLabel")}</Label>
            <Input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus disabled={submitting} />
            {mode === "enable-dual" && <p className="mt-1 text-xs text-[var(--color-text-muted)]">{t("security.dual.firstPasswordHint")}</p>}
          </div>
          {/* Segunda senha ATUAL: obrigatória sempre que o cofre já está no modo de duas senhas. */}
          {(needsCurrent2Here || throttleNeedsCurrent2) && <SecondPasswordField value={current2} onChange={setCurrent2} disabled={submitting} />}

          {needsNewSecond && (
            <>
              <div>
                <Label>{t("security.dual.newSecondLabel")}</Label>
                <Input type="password" value={newSecond} onChange={(e) => setNewSecond(e.target.value)} autoComplete="new-password" disabled={submitting} />
                <PasswordStrengthMeter password={newSecond} />
              </div>
              <div>
                <Label>{t("security.dual.confirmSecondLabel")}</Label>
                <Input type="password" value={confirmSecond} onChange={(e) => setConfirmSecond(e.target.value)} autoComplete="new-password" disabled={submitting} />
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
            <Button type="submit" variant={mode === "disable-dual" || mode === "throttle-off" ? "danger" : "primary"} disabled={submitting}>
              {submitting ? t("common.verifying") : t("security.dual.submit")}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
