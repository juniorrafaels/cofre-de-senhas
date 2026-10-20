import { FormEvent, useEffect, useState } from "react";
import { KeyRound, ShieldAlert, ShieldCheck } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Input, Label } from "../ui/Input";
import { securityQuestionCommands, recoveryKeyCommands, recoveryPasswordCommands } from "../../lib/tauri";
import { useSecurityStore } from "../../store/useSecurityStore";
import { useVaultStore } from "../../store/useVaultStore";
import { useToastStore } from "../../store/useToastStore";
import type { RecoveryQuestion } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

interface Props {
  open: boolean;
  onClose: () => void;
}

type Step =
  | "loading"
  | "unavailable"
  | "choose-method"
  | "recovery-key"
  | "recovery-password"
  | "answering"
  | "submitting"
  | "reset-password"
  | "done";

export function RecoveryFlow({ open, onClose }: Props) {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>("loading");
  const [unavailableReason, setUnavailableReason] = useState("");
  const [questionsAvailable, setQuestionsAvailable] = useState(false);
  const [recoveryKeyAvailable, setRecoveryKeyAvailable] = useState(false);
  const [recoveryPasswordAvailable, setRecoveryPasswordAvailable] = useState(false);
  const [recoveryPasswordInput, setRecoveryPasswordInput] = useState("");
  const [recoveryPasswordError, setRecoveryPasswordError] = useState<string | null>(null);
  const [recoveryPasswordSubmitting, setRecoveryPasswordSubmitting] = useState(false);
  const gate = useSecurityStore((s) => s.gate);
  const refreshGate = useSecurityStore((s) => s.refresh);
  const [questions, setQuestions] = useState<RecoveryQuestion[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [currentAnswer, setCurrentAnswer] = useState("");
  const [collected, setCollected] = useState<{ id: number; answer: string }[]>([]);
  const [failMessage, setFailMessage] = useState<string | null>(null);
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("");
  const [recoveryKeyError, setRecoveryKeyError] = useState<string | null>(null);
  const [recoveryKeySubmitting, setRecoveryKeySubmitting] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resetError, setResetError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const refreshVault = useVaultStore((s) => s.refresh);
  const push = useToastStore((s) => s.push);

  async function startQuestionsFlow() {
    const list = await securityQuestionCommands.getRecoveryQuestions();
    setQuestions(list);
    setCurrentIndex(0);
    setCurrentAnswer("");
    setCollected([]);
    setFailMessage(null);
    setStep("answering");
  }

  async function startFlow() {
    setStep("loading");
    setFailMessage(null);
    const [summary, keyStatus, passwordStatus] = await Promise.all([
      securityQuestionCommands.summary(),
      recoveryKeyCommands.status(),
      recoveryPasswordCommands.status().catch(() => ({ enabled: false, created_at: null })),
    ]);
    const hasQuestions = summary.count >= summary.min_required_for_recovery;
    const hasRecoveryKey = keyStatus.enabled;
    const hasRecoveryPassword = passwordStatus.enabled;
    setQuestionsAvailable(hasQuestions);
    setRecoveryKeyAvailable(hasRecoveryKey);
    setRecoveryPasswordAvailable(hasRecoveryPassword);
    setRecoveryPasswordInput("");
    setRecoveryPasswordError(null);

    if (!hasQuestions && !hasRecoveryKey && !hasRecoveryPassword) {
      setUnavailableReason(
        summary.count > 0
          ? t("recovery.unavailableWithCount", { min: summary.min_required_for_recovery, count: summary.count })
          : t("recovery.unavailableNone"),
      );
      setStep("unavailable");
      return;
    }

    const methodCount = [hasRecoveryKey, hasQuestions, hasRecoveryPassword].filter(Boolean).length;
    if (methodCount > 1) {
      setStep("choose-method");
    } else if (hasRecoveryKey) {
      setStep("recovery-key");
    } else if (hasRecoveryPassword) {
      setStep("recovery-password");
    } else {
      await startQuestionsFlow();
    }
  }

  useEffect(() => {
    if (open) startFlow();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function handleRecoveryKeySubmit(e: FormEvent) {
    e.preventDefault();
    setRecoveryKeySubmitting(true);
    setRecoveryKeyError(null);
    try {
      await recoveryKeyCommands.unlockWithKey(recoveryKeyInput);
      setRecoveryKeyInput("");
      setStep("reset-password");
    } catch (err) {
      setRecoveryKeyError(translateBackendError(t, err));
    } finally {
      setRecoveryKeySubmitting(false);
    }
  }

  async function handleRecoveryPasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setRecoveryPasswordSubmitting(true);
    setRecoveryPasswordError(null);
    try {
      await recoveryPasswordCommands.unlock(recoveryPasswordInput);
      setRecoveryPasswordInput("");
      await refreshGate();
      setStep("reset-password");
    } catch (err) {
      setRecoveryPasswordError(translateBackendError(t, err));
      // Traz do backend o bloqueio/estado atual (ex.: instância já aberta, bloqueio progressivo).
      await refreshGate();
    } finally {
      setRecoveryPasswordSubmitting(false);
    }
  }

  function handleNext(e: FormEvent) {
    e.preventDefault();
    const nextCollected = [...collected, { id: questions[currentIndex].id, answer: currentAnswer }];
    setCollected(nextCollected);
    setCurrentAnswer("");

    if (currentIndex + 1 < questions.length) {
      setCurrentIndex((i) => i + 1);
    } else {
      submitAnswers(nextCollected);
    }
  }

  async function submitAnswers(answers: { id: number; answer: string }[]) {
    setStep("submitting");
    try {
      const outcome = await securityQuestionCommands.attemptRecovery(answers);
      if (outcome.success) {
        setStep("reset-password");
      } else {
        setFailMessage(translateBackendError(t, outcome.message));
        setStep("answering");
        setCurrentIndex(0);
        setCurrentAnswer("");
        setCollected([]);
        const list = await securityQuestionCommands.getRecoveryQuestions();
        setQuestions(list);
      }
    } catch (err) {
      setFailMessage(translateBackendError(t, err));
      setStep("answering");
    }
  }

  async function handleResetPassword(e: FormEvent) {
    e.preventDefault();
    setResetError(null);
    if (newPassword.length < 8) {
      setResetError(t("recovery.resetTooShort"));
      return;
    }
    if (newPassword !== confirmPassword) {
      setResetError(t("recovery.resetMismatch"));
      return;
    }
    setSaving(true);
    try {
      await securityQuestionCommands.resetPasswordAfterRecovery(newPassword);
      await refreshVault();
      push(t("recovery.resetSuccessToast"), "success");
      setStep("done");
      onClose();
    } catch (err) {
      setResetError(translateBackendError(t, err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={t("recovery.title")} width="sm">
      {step === "loading" && <p className="text-sm text-[var(--color-text-muted)]">{t("recovery.loading")}</p>}

      {step === "unavailable" && (
        <div className="space-y-3">
          <div className="flex gap-3 rounded-lg border border-red-300 bg-red-50 p-3 text-red-900">
            <ShieldAlert size={18} className="mt-0.5 shrink-0" />
            <p className="text-sm">{unavailableReason}</p>
          </div>
          <div className="flex justify-end">
            <Button variant="secondary" onClick={onClose}>
              {t("common.close")}
            </Button>
          </div>
        </div>
      )}

      {step === "choose-method" && (
        <div className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">{t("recovery.chooseMethodPrompt")}</p>
          <div className="space-y-2">
            {recoveryKeyAvailable && (
              <Button variant="primary" className="w-full justify-start" onClick={() => setStep("recovery-key")}>
                <KeyRound size={14} /> {t("recovery.useRecoveryKey")}
              </Button>
            )}
            {questionsAvailable && (
              <Button variant="secondary" className="w-full justify-start" onClick={() => startQuestionsFlow()}>
                <ShieldCheck size={14} /> {t("recovery.useSecurityQuestions")}
              </Button>
            )}
            {recoveryPasswordAvailable && (
              <Button variant="secondary" className="w-full justify-start" onClick={() => setStep("recovery-password")}>
                <KeyRound size={14} /> {t("security.recoveryPassword.flow.option")}
              </Button>
            )}
          </div>
          <div className="flex justify-end pt-2">
            <Button variant="ghost" onClick={onClose}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}

      {step === "recovery-password" && (
        <form onSubmit={handleRecoveryPasswordSubmit} className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">{t("security.recoveryPassword.flow.prompt")}</p>
          {recoveryPasswordError && (
            <p role="alert" data-testid="recovery-password-error" className="text-sm text-[var(--color-danger)]">
              {recoveryPasswordError}
            </p>
          )}
          <div>
            <Label>{t("security.recoveryPassword.flow.label")}</Label>
            <Input
              type="password"
              value={recoveryPasswordInput}
              onChange={(e) => setRecoveryPasswordInput(e.target.value)}
              autoFocus
              disabled={recoveryPasswordSubmitting}
              autoComplete="off"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            {(recoveryKeyAvailable || questionsAvailable) && (
              <Button type="button" variant="ghost" onClick={() => setStep("choose-method")}>
                {t("recovery.chooseAnotherMethod")}
              </Button>
            )}
            <Button type="submit" variant="primary" disabled={!recoveryPasswordInput || recoveryPasswordSubmitting}>
              {recoveryPasswordSubmitting ? t("common.verifying") : t("common.confirm")}
            </Button>
          </div>
        </form>
      )}

      {step === "recovery-key" && (
        <form onSubmit={handleRecoveryKeySubmit} className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">{t("recovery.recoveryKeyPrompt")}</p>
          {recoveryKeyError && <p className="text-sm text-[var(--color-danger)]">{recoveryKeyError}</p>}
          <div>
            <Label>{t("recovery.recoveryKeyLabel")}</Label>
            <Input
              value={recoveryKeyInput}
              onChange={(e) => setRecoveryKeyInput(e.target.value)}
              autoFocus
              className="font-mono"
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
              disabled={recoveryKeySubmitting}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            {questionsAvailable && (
              <Button type="button" variant="ghost" onClick={() => startQuestionsFlow()}>
                {t("recovery.useQuestionsInstead")}
              </Button>
            )}
            <Button type="submit" variant="primary" disabled={!recoveryKeyInput.trim() || recoveryKeySubmitting}>
              {recoveryKeySubmitting ? t("common.verifying") : t("common.confirm")}
            </Button>
          </div>
        </form>
      )}

      {(step === "answering" || step === "submitting") && questions.length > 0 && (
        <form onSubmit={handleNext} className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">{t("recovery.questionsPrompt")}</p>
          {failMessage && <p className="text-sm text-[var(--color-danger)]">{failMessage}</p>}
          <p className="text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
            {t("recovery.questionCounter", { current: currentIndex + 1, total: questions.length })}
          </p>
          <div>
            <Label>{questions[currentIndex]?.question}</Label>
            <Input value={currentAnswer} onChange={(e) => setCurrentAnswer(e.target.value)} autoFocus disabled={step === "submitting"} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={onClose}>
              {t("common.cancel")}
            </Button>
            {recoveryKeyAvailable && currentIndex === 0 && (
              <Button type="button" variant="ghost" onClick={() => setStep("recovery-key")}>
                {t("recovery.useRecoveryKeyInstead")}
              </Button>
            )}
            <Button type="submit" variant="primary" disabled={!currentAnswer.trim() || step === "submitting"}>
              {step === "submitting" ? t("common.verifying") : currentIndex + 1 < questions.length ? t("recovery.next") : t("recovery.finish")}
            </Button>
          </div>
        </form>
      )}

      {step === "reset-password" && (
        <form onSubmit={handleResetPassword} className="space-y-3">
          <div className="flex gap-3 rounded-lg border border-emerald-300 bg-emerald-50 p-3 text-emerald-900">
            <ShieldCheck size={18} className="mt-0.5 shrink-0" />
            <p className="text-sm font-medium">{t("recovery.identityConfirmed")}</p>
          </div>
          {gate?.dual && (
            <p className="rounded-lg border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">{t("security.recoveryPassword.flow.resetNote")}</p>
          )}
          <div>
            <Label>{t("recovery.newPasswordLabel")}</Label>
            <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoFocus />
          </div>
          <div>
            <Label>{t("recovery.confirmNewPasswordLabel")}</Label>
            <Input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
          </div>
          {resetError && <p className="text-sm text-[var(--color-danger)]">{resetError}</p>}
          <div className="flex justify-end pt-2">
            <Button type="submit" variant="primary" disabled={saving}>
              <KeyRound size={14} /> {saving ? t("common.saving") : t("recovery.changePassword")}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
