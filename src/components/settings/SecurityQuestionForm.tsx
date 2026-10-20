import { FormEvent, useEffect, useState } from "react";
import { Modal } from "../ui/Modal";
import { Input, Label, Textarea } from "../ui/Input";
import { Button } from "../ui/Button";
import type { SecurityQuestion } from "../../types";
import { SecondPasswordField, useDualUnlock } from "../security/SecondPasswordField";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

interface Props {
  open: boolean;
  onClose: () => void;
  // Fase 4 (SECURITY_AUDIT_PHASE_4.md): adicionar/editar uma pergunta de segurança exige a senha
  // mestra atual, reverificada no Rust — alterar esse mecanismo de recuperação é uma operação
  // crítica.
  onSubmit: (currentPassword: string, question: string, answer?: string, currentPassword2?: string) => Promise<void>;
  editingQuestion: SecurityQuestion | null;
  // Quantas perguntas existirão depois de salvar (adicionar = atual + 1) e o mínimo para a
  // recuperação funcionar: abaixo disso a configuração parece válida mas NÃO recupera o cofre.
  questionCountAfterSave: number;
  minRequired: number;
}

export function SecurityQuestionForm({ open, onClose, onSubmit, editingQuestion, questionCountAfterSave, minRequired }: Props) {
  const { t } = useTranslation();
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [currentPassword2, setCurrentPassword2] = useState("");
  const dual = useDualUnlock();
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setQuestion(editingQuestion?.question ?? "");
    setAnswer("");
    setCurrentPassword("");
    setCurrentPassword2("");
    setError(null);
  }, [open, editingQuestion]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!question.trim()) {
      setError(t("settings.securityQuestions.form.questionRequiredError"));
      return;
    }
    if (!editingQuestion && !answer.trim()) {
      setError(t("settings.securityQuestions.form.answerRequiredError"));
      return;
    }
    if (!currentPassword || (dual && !currentPassword2)) {
      setError(t("settings.securityQuestions.form.passwordRequiredError"));
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSubmit(currentPassword, question.trim(), answer.trim() || undefined, dual ? currentPassword2 : undefined);
      onClose();
    } catch (err) {
      setError(translateBackendError(t, err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={editingQuestion ? t("settings.securityQuestions.form.titleEdit") : t("settings.securityQuestions.form.titleNew")} width="sm">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <Label>{t("settings.securityQuestions.form.questionLabel")}</Label>
          <Textarea rows={2} value={question} onChange={(e) => setQuestion(e.target.value)} autoFocus />
        </div>
        <div>
          <Label>
            {t("settings.securityQuestions.form.answerLabel")}
            {editingQuestion ? t("settings.securityQuestions.form.answerLabelEditHint") : ""}
          </Label>
          <Input
            type="text"
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
            placeholder={editingQuestion ? t("settings.securityQuestions.form.answerPlaceholderEdit") : ""}
          />
          <p className="mt-1 text-xs text-[var(--color-text-muted)]">{t("settings.securityQuestions.form.answerHint")}</p>
        </div>

        <div>
          <Label>{t("settings.securityQuestions.form.masterPasswordLabel")}</Label>
          <Input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder={t("settings.securityQuestions.form.masterPasswordPlaceholder")}
          />
        </div>
        <SecondPasswordField value={currentPassword2} onChange={setCurrentPassword2} disabled={saving} />

        {questionCountAfterSave < minRequired && (
          <p role="alert" className="rounded-lg border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">
            {t("settings.securityQuestions.form.belowThresholdWarning", { count: questionCountAfterSave, min: minRequired })}
          </p>
        )}

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={saving}>
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
