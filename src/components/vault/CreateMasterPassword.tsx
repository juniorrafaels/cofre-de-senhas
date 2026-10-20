import { FormEvent, useState } from "react";
import { ShieldCheck } from "lucide-react";
import clsx from "clsx";
import { Button } from "../ui/Button";
import { Input, Label } from "../ui/Input";
import { useVaultStore } from "../../store/useVaultStore";
import { useSettingsStore } from "../../store/useSettingsStore";
import { PasswordStrengthMeter } from "../ui/PasswordStrengthMeter";
import { useTranslation } from "../../i18n";
import { SUPPORTED_LOCALES, type Locale } from "../../types";

const LANGUAGE_LABEL_KEYS: Record<Locale, string> = {
  "pt-BR": "settings.appearance.languagePortuguese",
  en: "settings.appearance.languageEnglish",
  es: "settings.appearance.languageSpanish",
};

export function CreateMasterPassword() {
  const create = useVaultStore((s) => s.create);
  const setLanguage = useSettingsStore((s) => s.setLanguage);
  const { t, locale, setLocale } = useTranslation();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 8) {
      setError(t("onboarding.errorTooShort"));
      return;
    }
    if (password !== confirm) {
      setError(t("onboarding.errorMismatch"));
      return;
    }
    setLoading(true);
    try {
      await create(password);
      // A tabela `settings` só existe depois que o cofre é criado (seção 14 do pedido de i18n) —
      // persistimos a escolha feita no onboarding só agora, embora a UI já a aplicasse antes.
      await setLanguage(locale);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
      <form onSubmit={handleSubmit} className="w-full max-w-sm rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-7 shadow-xl animate-scale-in">
        <div className="mb-5 flex flex-col items-center gap-3 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="text-lg font-semibold">{t("onboarding.title")}</h1>
            <p className="mt-1 text-sm text-[var(--color-text-muted)]">{t("onboarding.subtitle")}</p>
          </div>
        </div>

        <div className="mb-4">
          <Label>{t("onboarding.languageLabel")}</Label>
          <div className="flex gap-1.5">
            {SUPPORTED_LOCALES.map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setLocale(option)}
                className={clsx(
                  "flex-1 rounded-lg border px-2.5 py-1.5 text-sm transition-colors",
                  locale === option
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]",
                )}
              >
                {t(LANGUAGE_LABEL_KEYS[option])}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-3">
          <div>
            <Label>{t("onboarding.masterPasswordLabel")}</Label>
            <Input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
            {/* Avaliador compartilhado (src/lib/passwordStrength.ts), agrupado nos mesmos 3 níveis de antes. */}
            <PasswordStrengthMeter password={password} granularity="three" />
          </div>
          <div>
            <Label>{t("onboarding.confirmPasswordLabel")}</Label>
            <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </div>
        </div>

        {error && <p className="mt-3 text-sm text-[var(--color-danger)]">{error}</p>}

        <Button type="submit" variant="primary" className="mt-5 w-full" disabled={loading}>
          {loading ? t("onboarding.submitting") : t("onboarding.submit")}
        </Button>
      </form>
    </div>
  );
}
