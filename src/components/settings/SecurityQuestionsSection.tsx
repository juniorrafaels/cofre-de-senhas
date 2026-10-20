import { FormEvent, useCallback, useEffect, useState } from "react";
import { AlertTriangle, HelpCircle, Pencil, Plus, Printer, Trash2 } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { SecurityQuestionForm } from "./SecurityQuestionForm";
import { RecoveryKitDialog } from "./RecoveryKitDialog";
import { listSecurityQuestions } from "../../lib/db";
import { securityQuestionCommands } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import type { SecurityQuestion } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";
import { SecondPasswordField, useDualUnlock } from "../security/SecondPasswordField";

// Recuperação por perguntas de segurança: recurso OPCIONAL (decisão do proprietário). Cada resposta
// protege, sozinha, uma share de Shamir da chave de dados — quem obtiver o arquivo do cofre pode
// testar cada resposta offline, uma de cada vez (ver SECURITY.md). Por isso o aviso de riscos fica
// sempre visível aqui, sem impedir a configuração.
const MAX_QUESTIONS = 20;
const DEFAULT_MIN_REQUIRED = 3;

export function SecurityQuestionsSection() {
  const { t } = useTranslation();
  const [questions, setQuestions] = useState<SecurityQuestion[]>([]);
  const [minRequired, setMinRequired] = useState(DEFAULT_MIN_REQUIRED);
  const [loading, setLoading] = useState(true);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<SecurityQuestion | null>(null);
  const [pendingDelete, setPendingDelete] = useState<SecurityQuestion | null>(null);
  const [deletePassword, setDeletePassword] = useState("");
  const [deletePassword2, setDeletePassword2] = useState("");
  const dual = useDualUnlock();
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const push = useToastStore((s) => s.push);

  const refresh = useCallback(async () => {
    const [list, summary] = await Promise.all([listSecurityQuestions(), securityQuestionCommands.summary()]);
    setQuestions(list);
    setMinRequired(summary.min_required_for_recovery);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleSubmit(currentPassword: string, question: string, answer?: string, currentPassword2?: string) {
    if (editing) {
      await securityQuestionCommands.update(currentPassword, editing.id, question, answer, currentPassword2);
      push(t("settings.securityQuestions.updatedToast"), "success");
    } else {
      if (questions.length >= MAX_QUESTIONS) {
        push(t("settings.securityQuestions.limitReached", { max: MAX_QUESTIONS }), "error");
        return;
      }
      await securityQuestionCommands.add(currentPassword, question, answer ?? "", currentPassword2);
      push(t("settings.securityQuestions.addedToast"), "success");
    }
    await refresh();
  }

  function closeDeleteDialog() {
    setPendingDelete(null);
    setDeletePassword("");
    setDeletePassword2("");
    setDeleteError(null);
  }

  // Fase 4 (SECURITY_AUDIT_PHASE_4.md): remover uma pergunta também exige a senha mestra atual —
  // destrói parte do mecanismo de recuperação, mesmo padrão de reautenticação da Recovery Key.
  async function handleDelete(e: FormEvent) {
    e.preventDefault();
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await securityQuestionCommands.remove(deletePassword, pendingDelete.id, dual ? deletePassword2 : undefined);
      closeDeleteDialog();
      await refresh();
      push(t("settings.securityQuestions.removedToast"), "success");
    } catch (err) {
      setDeleteError(translateBackendError(t, err));
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-3 border-t border-[var(--color-border)] pt-4">
      <div className="flex items-center gap-2 text-sm font-medium">
        <HelpCircle size={15} /> {t("settings.securityQuestions.title")}
      </div>

      <p className="text-xs text-[var(--color-text-muted)]">
        <strong>{t("settings.securityQuestions.optionalTitle")}.</strong> {t("settings.securityQuestions.optionalBody")}
      </p>

      <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">
        <AlertTriangle size={18} className="mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="text-sm font-semibold">{t("settings.securityQuestions.risksTitle")}</p>
          <ul className="list-disc space-y-1 pl-4 text-xs">
            <li>{t("settings.securityQuestions.riskOffline")}</li>
            <li>{t("settings.securityQuestions.riskGuessable")}</li>
            <li>{t("settings.securityQuestions.riskQuantity")}</li>
            <li>{t("settings.securityQuestions.riskRecoveryKey")}</li>
            <li>{t("settings.securityQuestions.riskEndpoint")}</li>
          </ul>
        </div>
      </div>

      {!loading && (
        <div className="space-y-1">
          <p className="text-sm text-[var(--color-text)]">{t("settings.securityQuestions.countLabel", { count: questions.length })}</p>
          {questions.length > 0 && (
            <p className="text-xs text-[var(--color-text-muted)]">
              {questions.length < minRequired
                ? t("settings.securityQuestions.thresholdInactive", { count: questions.length, min: minRequired })
                : t("settings.securityQuestions.thresholdActive", { min: minRequired })}
            </p>
          )}
        </div>
      )}

      <div className="space-y-1">
        {questions.map((q, i) => (
          <div key={q.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-[var(--color-surface-hover)]">
            <span className="w-5 shrink-0 text-xs text-[var(--color-text-muted)]">{i + 1}.</span>
            <span className="flex-1 truncate text-sm">{q.question}</span>
            <button
              onClick={() => {
                setEditing(q);
                setFormOpen(true);
              }}
              title={t("settings.securityQuestions.editButton")}
              aria-label={t("settings.securityQuestions.editButton")}
              className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
            >
              <Pencil size={13} />
            </button>
            <button
              onClick={() => setPendingDelete(q)}
              title={t("settings.securityQuestions.removeButton")}
              aria-label={t("settings.securityQuestions.removeButton")}
              className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-danger)]"
            >
              <Trash2 size={13} />
            </button>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            setEditing(null);
            setFormOpen(true);
          }}
          disabled={questions.length >= MAX_QUESTIONS}
          title={questions.length >= MAX_QUESTIONS ? t("settings.securityQuestions.limitReached", { max: MAX_QUESTIONS }) : undefined}
        >
          <Plus size={14} /> {t("settings.securityQuestions.add")}
        </Button>
        {questions.length > 0 && (
          <Button variant="secondary" size="sm" onClick={() => setExportOpen(true)}>
            <Printer size={14} /> {t("settings.securityQuestions.exportButton")}
          </Button>
        )}
      </div>
      {questions.length >= MAX_QUESTIONS && (
        <p className="text-xs text-[var(--color-danger)]">{t("settings.securityQuestions.limitReached", { max: MAX_QUESTIONS })}</p>
      )}

      <SecurityQuestionForm
        open={formOpen}
        onClose={() => setFormOpen(false)}
        onSubmit={handleSubmit}
        editingQuestion={editing}
        questionCountAfterSave={editing ? questions.length : questions.length + 1}
        minRequired={minRequired}
      />

      <Modal open={!!pendingDelete} onClose={closeDeleteDialog} title={t("settings.securityQuestions.removeTitle")} width="sm">
        <form onSubmit={handleDelete} className="space-y-3">
          <p className="text-sm text-[var(--color-text-muted)]">
            {t("settings.securityQuestions.removeConfirm", { question: pendingDelete?.question ?? "" })}
          </p>
          <div>
            <Label>{t("settings.securityQuestions.masterPasswordLabel")}</Label>
            <Input
              type="password"
              value={deletePassword}
              onChange={(e) => setDeletePassword(e.target.value)}
              autoFocus
              disabled={deleting}
            />
          </div>
          <SecondPasswordField value={deletePassword2} onChange={setDeletePassword2} disabled={deleting} />
          {deleteError && <p className="text-sm text-[var(--color-danger)]">{deleteError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={closeDeleteDialog} disabled={deleting}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="danger" disabled={!deletePassword || (dual && !deletePassword2) || deleting}>
              {deleting ? t("settings.securityQuestions.removing") : t("settings.securityQuestions.removeButton")}
            </Button>
          </div>
        </form>
      </Modal>

      <RecoveryKitDialog open={exportOpen} onClose={() => setExportOpen(false)} />
    </div>
  );
}
