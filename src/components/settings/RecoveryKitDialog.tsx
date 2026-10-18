import { useEffect, useState } from "react";
import { AlertTriangle, Printer } from "lucide-react";
import { createPortal } from "react-dom";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { listSecurityQuestions } from "../../lib/db";
import type { SecurityQuestion } from "../../types";
import { useTranslation } from "../../i18n";

interface Props {
  open: boolean;
  onClose: () => void;
  // Quando presente, o kit inclui a Recovery Key recém-gerada (só é passada uma vez, pelo
  // chamador — este componente nunca busca ou re-exibe uma chave antiga, porque não existe:
  // o backend não guarda a chave em texto puro em lugar nenhum).
  recoveryKey?: string | null;
}

export function RecoveryKitDialog({ open, onClose, recoveryKey }: Props) {
  const { t } = useTranslation();
  const [step, setStep] = useState<"warning" | "sheet">("warning");
  const [questions, setQuestions] = useState<SecurityQuestion[]>([]);

  useEffect(() => {
    if (open) setStep("warning");
  }, [open]);

  async function handleConfirm() {
    const list = await listSecurityQuestions();
    setQuestions(list);
    setStep("sheet");
  }

  function handleCloseSheet() {
    setStep("warning");
    onClose();
  }

  if (open && step === "sheet") {
    return createPortal(
      <div className="fixed inset-0 z-[200] overflow-y-auto bg-[var(--color-bg)]">
        <div className="mx-auto max-w-2xl p-8">
          <div className="mb-6 flex items-center justify-between print:hidden">
            <Button variant="ghost" onClick={handleCloseSheet}>
              {t("common.close")}
            </Button>
            <Button variant="primary" onClick={() => window.print()}>
              <Printer size={15} /> {t("settings.recoveryKit.print")}
            </Button>
          </div>

          <div id="print-sheet" className="rounded-xl border border-[var(--color-border)] bg-white p-10 text-black print:border-0 print:p-0">
            <h1 className="mb-1 text-xl font-bold">{t("settings.recoveryKit.sheetTitle")}</h1>
            <p className="mb-6 text-sm text-gray-600">{t("settings.recoveryKit.sheetIntro")}</p>

            {recoveryKey && (
              <div className="mb-8">
                <h2 className="mb-2 text-base font-semibold">{t("settings.recoveryKit.recoveryKeyHeading")}</h2>
                <p className="mb-2 text-sm text-gray-600">{t("settings.recoveryKit.recoveryKeyBody")}</p>
                <p className="rounded-lg border border-gray-400 bg-gray-50 p-3 text-center font-mono text-lg tracking-wider">
                  {recoveryKey}
                </p>
              </div>
            )}

            {questions.length > 0 && (
              <div>
                <h2 className="mb-2 text-base font-semibold">{t("settings.recoveryKit.questionsHeading")}</h2>
                <p className="mb-4 text-sm text-gray-600">{t("settings.recoveryKit.questionsBody")}</p>
                <ol className="space-y-5">
                  {questions.map((q, i) => (
                    <li key={q.id}>
                      <p className="font-medium">
                        {i + 1}. {q.question}
                      </p>
                      <div className="mt-2 h-px w-full border-b border-dashed border-gray-400" />
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        </div>
      </div>,
      document.body,
    );
  }

  return (
    <Modal open={open} onClose={onClose} title={t("settings.recoveryKit.exportTitle")} width="sm">
      <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">
        <AlertTriangle size={18} className="mt-0.5 shrink-0" />
        <div className="text-sm">
          <p className="font-semibold">{t("settings.recoveryKit.warningTitle")}</p>
          <p className="mt-1">{t("settings.recoveryKit.warningBody1")}</p>
          <p className="mt-1">{t("settings.recoveryKit.warningBody2")}</p>
          <p className="mt-1">{t("settings.recoveryKit.warningBody3")}</p>
        </div>
      </div>

      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          {t("common.cancel")}
        </Button>
        <Button variant="primary" onClick={handleConfirm}>
          {t("settings.recoveryKit.continueLabel")}
        </Button>
      </div>
    </Modal>
  );
}
