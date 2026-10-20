import { FormEvent, useEffect, useState } from "react";
import { AlertTriangle, Lock, ShieldAlert, Timer } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { useVaultStore } from "../../store/useVaultStore";
import { EMPTY_GATE, useSecurityStore } from "../../store/useSecurityStore";
import { RecoveryFlow } from "./RecoveryFlow";
import { useTranslation } from "../../i18n";
import { parseStructuredError, translateBackendError } from "../../i18n/backendErrors";
import { formatWait } from "../../lib/duration";
import { useCountdown } from "../../lib/useCountdown";

/** Intervalo para detectar que a outra instância bloqueou o cofre (libera esta tela). */
const OPEN_ELSEWHERE_POLL_MS = 3000;

export function UnlockScreen() {
  const unlock = useVaultStore((s) => s.unlock);
  const gate = useSecurityStore((s) => s.gate);
  const refreshGate = useSecurityStore((s) => s.refresh);
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  const dual = gate?.dual ?? false;
  const openElsewhere = gate?.open_elsewhere ?? false;
  // A fonte da verdade do bloqueio é o backend; aqui só se desenha a contagem regressiva.
  const remaining = useCountdown(gate?.locked ? gate.remaining_seconds : 0, gate, () => {
    refreshGate();
  });
  const blocked = remaining > 0;

  useEffect(() => {
    refreshGate();
  }, [refreshGate]);

  useEffect(() => {
    if (!openElsewhere) return;
    const id = window.setInterval(() => {
      refreshGate();
    }, OPEN_ELSEWHERE_POLL_MS);
    return () => window.clearInterval(id);
  }, [openElsewhere, refreshGate]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (blocked || openElsewhere) return;
    setError(null);
    setLoading(true);
    try {
      await unlock(password, dual ? password2 : undefined);
      setPassword("");
      setPassword2("");
    } catch (err) {
      setError(translateBackendError(t, err));
      setPassword("");
      setPassword2("");
      // Traz do backend o novo tempo de espera / a política atual (ex.: a segunda senha passou a
      // ser exigida), em vez de adivinhar no frontend.
      const refreshed = await refreshGate();
      // Se o backend diz que falta a segunda senha mas a consulta de estado não chegou (ou veio
      // desatualizada), mostra o segundo campo mesmo assim — nunca deixa o usuário sem como digitá-la.
      if (parseStructuredError(err)?.code === "second_password_required" && !refreshed?.dual) {
        useSecurityStore.setState((s) => ({ gate: { ...(refreshed ?? s.gate ?? EMPTY_GATE), dual: true } }));
      }
    } finally {
      setLoading(false);
    }
  }

  const canSubmit = !!password && (!dual || !!password2) && !loading && !blocked && !openElsewhere;

  return (
    <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-7 shadow-xl animate-scale-in">
        <div className="mb-5 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
            <Lock size={24} />
          </div>
          <div>
            <h1 className="text-lg font-semibold">{t("unlock.title")}</h1>
            <p className="mt-1 text-sm text-[var(--color-text-muted)]">{dual ? t("security.unlock.dualNotice") : t("unlock.subtitle")}</p>
          </div>
        </div>

        {openElsewhere && (
          <div role="alert" data-testid="open-elsewhere" className="mb-3 flex gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900">
            <AlertTriangle size={16} className="mt-0.5 shrink-0" />
            <p>{t("security.unlock.openElsewhere")}</p>
          </div>
        )}

        {gate?.protection_corrupt && (
          <div role="alert" data-testid="protection-corrupt" className="mb-3 flex gap-2 rounded-lg border border-red-300 bg-red-50 p-3 text-xs text-red-900">
            <ShieldAlert size={16} className="mt-0.5 shrink-0" />
            <p>{t("security.unlock.protectionCorrupt")}</p>
          </div>
        )}

        {blocked && (
          <div role="alert" data-testid="lockout-banner" className="mb-3 flex gap-2 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900">
            <Timer size={16} className="mt-0.5 shrink-0" />
            <div>
              <p className="font-medium">{t("security.unlock.lockedBanner", { time: formatWait(remaining) })}</p>
              {!!gate && gate.failed_count > 0 && <p className="mt-0.5">{t("security.unlock.failuresCount", { count: gate.failed_count })}</p>}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <Input
            type="password"
            autoFocus
            placeholder={dual ? t("security.unlock.firstPasswordPlaceholder") : t("unlock.passwordPlaceholder")}
            aria-label={dual ? t("security.unlock.firstPasswordPlaceholder") : t("unlock.passwordPlaceholder")}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={blocked || openElsewhere}
          />
          {dual && (
            <Input
              type="password"
              placeholder={t("security.unlock.secondPasswordPlaceholder")}
              aria-label={t("security.unlock.secondPasswordPlaceholder")}
              value={password2}
              onChange={(e) => setPassword2(e.target.value)}
              disabled={blocked || openElsewhere}
            />
          )}
        </div>

        {error && (
          <p role="alert" data-testid="unlock-error" className="mt-3 text-sm text-[var(--color-danger)]">
            {error}
          </p>
        )}

        <Button type="submit" variant="primary" className="mt-5 w-full" disabled={!canSubmit}>
          {loading ? t("unlock.submitting") : t("unlock.submit")}
        </Button>

        <button
          type="button"
          onClick={() => setRecoveryOpen(true)}
          className="mt-3 w-full text-center text-sm text-[var(--color-text-muted)] hover:text-[var(--color-accent)]"
        >
          {t("unlock.forgotPassword")}
        </button>
      </form>

      <RecoveryFlow open={recoveryOpen} onClose={() => setRecoveryOpen(false)} />
    </div>
  );
}
