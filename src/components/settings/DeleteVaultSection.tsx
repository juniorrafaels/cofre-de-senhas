import { FormEvent, useState } from "react";
import { AlertTriangle, Trash2 } from "lucide-react";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { vaultCommands } from "../../lib/tauri";
import { useVaultStore } from "../../store/useVaultStore";
import { useToastStore } from "../../store/useToastStore";
import { SecondPasswordField, useDualUnlock } from "../security/SecondPasswordField";
import { DEFAULT_LOCALE, useLocaleStore, useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

type Step = "idle" | "password" | "confirm";

// Exclusão completa do cofre (Configurações → Dados → Zona de perigo). Duas confirmações
// independentes e sequenciais, como pedido:
//  1) senha mestra atual, reautenticada de verdade no Rust (`verify_master_password` decifra o
//     wrapped_dek — não é uma comparação de flag no frontend);
//  2) digitar exatamente a palavra de confirmação (EXCLUIR/DELETE/ELIMINAR conforme o idioma
//     ativo — ver `deleteVault.confirmWord` nos locales).
// Só depois das duas o backend (`delete_vault`) reautentica a senha uma última vez e apaga tudo.
export function DeleteVaultSection() {
  const { t } = useTranslation();
  const confirmWord = t("deleteVault.confirmWord");
  const [step, setStep] = useState<Step>("idle");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const dual = useDualUnlock();
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [deleting, setDeleting] = useState(false);
  const refreshVault = useVaultStore((s) => s.refresh);
  const push = useToastStore((s) => s.push);

  function resetAll() {
    setStep("idle");
    setPassword("");
    setPassword2("");
    setPasswordError(null);
    setConfirmText("");
  }

  async function handleVerifyPassword(e: FormEvent) {
    e.preventDefault();
    setVerifying(true);
    setPasswordError(null);
    try {
      await vaultCommands.verifyMasterPassword(password, dual ? password2 : undefined);
      setStep("confirm");
    } catch (err) {
      setPasswordError(translateBackendError(t, err));
    } finally {
      setVerifying(false);
    }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await vaultCommands.deleteVault(password, dual ? password2 : undefined);
      resetAll();
      push(t("deleteVault.successToast"), "success");
      // Ao voltar para o fluxo de criação de um novo cofre, o idioma reinicia em português
      // (seção 10 do pedido de i18n) — não deve depender de resíduos do cofre anterior.
      useLocaleStore.getState().setLocale(DEFAULT_LOCALE);
      await refreshVault();
    } catch (err) {
      push(t("deleteVault.failToast", { error: translateBackendError(t, err) }), "error");
      resetAll();
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-3 rounded-xl border border-[var(--color-danger)]/40 bg-[var(--color-danger)]/5 p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-[var(--color-danger)]">
        <AlertTriangle size={15} /> {t("deleteVault.dangerZoneTitle")}
      </div>
      <p className="text-xs text-[var(--color-text-muted)]">{t("deleteVault.description")}</p>
      <Button variant="danger" size="sm" onClick={() => setStep("password")}>
        <Trash2 size={14} /> {t("deleteVault.deleteButton")}
      </Button>

      <Modal open={step === "password"} onClose={resetAll} title={t("deleteVault.passwordStepTitle")} width="sm">
        <form onSubmit={handleVerifyPassword} className="space-y-3">
          <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <p className="text-sm">{t("deleteVault.passwordStepWarning")}</p>
          </div>
          <div>
            <Label>{t("deleteVault.currentPasswordLabel")}</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
              disabled={verifying}
            />
          </div>
          <SecondPasswordField value={password2} onChange={setPassword2} disabled={verifying} />
          {passwordError && <p className="text-sm text-[var(--color-danger)]">{passwordError}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={resetAll} disabled={verifying}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="danger" disabled={!password || (dual && !password2) || verifying}>
              {verifying ? t("common.verifying") : t("common.continue")}
            </Button>
          </div>
        </form>
      </Modal>

      <Modal open={step === "confirm"} onClose={resetAll} title={t("deleteVault.confirmStepTitle")} width="sm">
        <div className="space-y-3">
          <div className="flex gap-3 rounded-lg border border-[var(--color-danger)]/40 bg-[var(--color-danger)]/10 p-3 text-[var(--color-danger)]">
            <AlertTriangle size={18} className="mt-0.5 shrink-0" />
            <div className="text-sm">
              <p className="font-medium">{t("deleteVault.confirmStepIntro")}</p>
              <ul className="ml-4 mt-1.5 list-disc space-y-0.5">
                <li>{t("deleteVault.listAccounts")}</li>
                <li>{t("deleteVault.listProjects")}</li>
                <li>{t("deleteVault.listPlatforms")}</li>
                <li>{t("deleteVault.listSettings")}</li>
                <li>{t("deleteVault.listImages")}</li>
              </ul>
              <p className="mt-1.5 font-medium">{t("deleteVault.cannotUndo")}</p>
            </div>
          </div>
          <div>
            <Label>{t("deleteVault.typeToConfirm", { word: confirmWord })}</Label>
            <Input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder={confirmWord}
              autoFocus
              disabled={deleting}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="ghost" onClick={resetAll} disabled={deleting}>
              {t("common.cancel")}
            </Button>
            <Button variant="danger" disabled={confirmText !== confirmWord || deleting} onClick={handleDelete}>
              {deleting ? t("deleteVault.deleting") : t("deleteVault.deleteFinal")}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
