import { FormEvent, useState } from "react";
import { Lock } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { useVaultStore } from "../../store/useVaultStore";
import { RecoveryFlow } from "./RecoveryFlow";
import { useTranslation } from "../../i18n";

export function UnlockScreen() {
  const unlock = useVaultStore((s) => s.unlock);
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [recoveryOpen, setRecoveryOpen] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await unlock(password);
    } catch (err) {
      setError(String(err));
      setPassword("");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-7 shadow-xl animate-scale-in">
        <div className="mb-5 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
            <Lock size={24} />
          </div>
          <div>
            <h1 className="text-lg font-semibold">{t("unlock.title")}</h1>
            <p className="mt-1 text-sm text-[var(--color-text-muted)]">{t("unlock.subtitle")}</p>
          </div>
        </div>

        <Input
          type="password"
          autoFocus
          placeholder={t("unlock.passwordPlaceholder")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {error && <p className="mt-3 text-sm text-[var(--color-danger)]">{error}</p>}

        <Button type="submit" variant="primary" className="mt-5 w-full" disabled={loading || !password}>
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
