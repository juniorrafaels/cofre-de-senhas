import { FormEvent, useCallback, useEffect, useState } from "react";
import { AlertTriangle, HelpCircle, Printer, Trash2 } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { RecoveryKitDialog } from "./RecoveryKitDialog";
import { listSecurityQuestions } from "../../lib/db";
import { securityQuestionCommands } from "../../lib/tauri";
import { useToastStore } from "../../store/useToastStore";
import type { SecurityQuestion } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

// Perguntas de segurança estão DESCONTINUADAS (auditoria de segurança): cada resposta protegia,
// sozinha, uma parte da chave de recuperação — quem obtiver o arquivo do cofre consegue testar
// cada resposta offline, uma de cada vez. Não é mais possível adicionar nem editar perguntas
// (o backend recusa); quem já tem perguntas ainda pode usá-las para recuperar o acesso, e pode
// (e deve) removê-las depois de gerar uma Recovery Key.
export function SecurityQuestionsSection() {
  const { t } = useTranslation();
  const [questions, setQuestions] = useState<SecurityQuestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [pendingDelete, setPendingDelete] = useState<SecurityQuestion | null>(null);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const push = useToastStore((s) => s.push);

  const refresh = useCallback(async () => {
    const list = await listSecurityQuestions();
    setQuestions(list);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function closeDeleteDialog() {
    setPendingDelete(null);
    setDeletePassword("");
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
      await securityQuestionCommands.remove(deletePassword, pendingDelete.id);
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

      <div role="alert" className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">
        <AlertTriangle size={18} className="mt-0.5 shrink-0" />
        <div className="space-y-1">
          <p className="text-sm font-semibold">{t("settings.securityQuestions.deprecatedTitle")}</p>
          <p className="text-xs">{t("settings.securityQuestions.deprecatedBody")}</p>
          {questions.length > 0 && <p className="text-xs font-medium">{t("settings.securityQuestions.deprecatedAction")}</p>}
        </div>
      </div>

      {!loading && <p className="text-sm text-[var(--color-text)]">{t("settings.securityQuestions.countLabel", { count: questions.length })}</p>}

      <div className="space-y-1">
        {questions.map((q, i) => (
          <div key={q.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-[var(--color-surface-hover)]">
            <span className="w-5 shrink-0 text-xs text-[var(--color-text-muted)]">{i + 1}.</span>
            <span className="flex-1 truncate text-sm">{q.question}</span>
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

      {questions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" size="sm" onClick={() => setExportOpen(true)}>
            <Printer size={14} /> {t("settings.securityQuestions.exportButton")}
          </Button>
        </div>
      )}

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
          {deleteError && <p className="text-sm text-[var(--color-danger)]">{deleteError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={closeDeleteDialog} disabled={deleting}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="danger" disabled={!deletePassword || deleting}>
              {deleting ? t("settings.securityQuestions.removing") : t("settings.securityQuestions.removeButton")}
            </Button>
          </div>
        </form>
      </Modal>

      <RecoveryKitDialog open={exportOpen} onClose={() => setExportOpen(false)} />
    </div>
  );
}
