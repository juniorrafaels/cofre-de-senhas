import { useEffect, useState } from "react";
import { AlertTriangle, Copy, RefreshCw, Wand2 } from "lucide-react";
import { Button } from "../ui/Button";
import { Input, Label } from "../ui/Input";
import { clipboardCommands, passwordGeneratorCommands } from "../../lib/tauri";
import { useCopySecret } from "../../lib/useCopy";
import { useToastStore } from "../../store/useToastStore";
import type { PasswordCharClass, PasswordCountMode, PasswordGeneratorOptions } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

const MIN_LENGTH = 4;
const MAX_LENGTH = 128;

interface ClassState {
  enabled: boolean;
  mode: PasswordCountMode;
  count: number;
}

type ClassesState = Record<PasswordCharClass, ClassState>;

const DEFAULT_CLASSES: ClassesState = {
  numbers: { enabled: true, mode: "auto", count: 4 },
  upper: { enabled: true, mode: "auto", count: 4 },
  lower: { enabled: true, mode: "auto", count: 4 },
  special: { enabled: false, mode: "auto", count: 4 },
};

const CLASS_KEYS: { key: PasswordCharClass; labelKey: string }[] = [
  { key: "numbers", labelKey: "settings.generator.classNumbers" },
  { key: "upper", labelKey: "settings.generator.classUpper" },
  { key: "lower", labelKey: "settings.generator.classLower" },
  { key: "special", labelKey: "settings.generator.classSpecial" },
];

function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min;
  return Math.min(max, Math.max(min, value));
}

// Gerador de senhas (Configurações → Gerador de Senhas). A geração em si roda inteiramente no
// Rust com CSPRNG (`generate_password` — ver src-tauri/src/commands/password_generator.rs); este
// componente só monta as regras e exibe o resultado. A senha gerada nunca é salva automaticamente
// nem persistida — só existe neste estado do React até a tela ser fechada ou outra ser gerada.
export function PasswordGeneratorSection() {
  const { t } = useTranslation();
  const [length, setLength] = useState(16);
  const [classes, setClasses] = useState<ClassesState>(DEFAULT_CLASSES);
  const [startType, setStartType] = useState<PasswordCharClass | "none">("none");
  const [endType, setEndType] = useState<PasswordCharClass | "none">("none");
  const [avoidSequences, setAvoidSequences] = useState(false);
  const [password, setPassword] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  // Senha gerada = segredo: copiada pelo caminho que, no Windows, a mantém fora do Histórico
  // (Win+V) e da sincronização em nuvem da área de transferência.
  const copySecret = useCopySecret();
  const push = useToastStore((s) => s.push);

  function updateClass(key: PasswordCharClass, patch: Partial<ClassState>) {
    setClasses((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }));
  }

  const enabledKeys = CLASS_KEYS.filter((c) => classes[c.key].enabled).map((c) => c.key);
  const atLeastOneEnabled = enabledKeys.length > 0;
  const fixedSum = enabledKeys.reduce((sum, key) => (classes[key].mode === "fixed" ? sum + classes[key].count : sum), 0);
  const anyFixedExceedsLength = enabledKeys.some((key) => classes[key].mode === "fixed" && classes[key].count > length);
  const sumExceedsLength = fixedSum > length;

  function classAvailable(key: PasswordCharClass): boolean {
    const c = classes[key];
    if (!c.enabled) return false;
    if (c.mode === "auto") return true;
    return c.count > 0;
  }

  // Se o tipo escolhido para começar/terminar deixar de ser válido (foi desabilitado, ou a
  // quantidade definida virou 0), volta para "sem preferência" em vez de deixar uma seleção
  // impossível pendente.
  useEffect(() => {
    if (startType !== "none" && !classAvailable(startType)) setStartType("none");
    if (endType !== "none" && !classAvailable(endType)) setEndType("none");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [classes]);

  const sameStartEndTooSmall =
    startType !== "none" &&
    startType === endType &&
    length > 1 &&
    classes[startType].mode === "fixed" &&
    classes[startType].count < 2;

  const canGenerate = atLeastOneEnabled && !sumExceedsLength && !anyFixedExceedsLength && !sameStartEndTooSmall && !generating;

  async function handleGenerate() {
    setGenerating(true);
    try {
      const options: PasswordGeneratorOptions = {
        length,
        numbers: classes.numbers,
        upper: classes.upper,
        lower: classes.lower,
        special: classes.special,
        startType: startType === "none" ? null : startType,
        endType: endType === "none" ? null : endType,
        avoidSequences,
      };
      const generated = await passwordGeneratorCommands.generate(options);
      setPassword(generated);
    } catch (err) {
      push(translateBackendError(t, err), "error");
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <Label>{t("settings.generator.lengthLabel")}</Label>
        <Input
          type="number"
          min={MIN_LENGTH}
          max={MAX_LENGTH}
          value={length}
          onChange={(e) => setLength(clamp(Number(e.target.value), MIN_LENGTH, MAX_LENGTH))}
          className="w-24"
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">{t("settings.generator.lengthHint", { min: MIN_LENGTH, max: MAX_LENGTH })}</p>
      </div>

      <div className="space-y-2">
        {CLASS_KEYS.map(({ key, labelKey }) => (
          <div key={key} className="rounded-lg border border-[var(--color-border)] p-3">
            <label className="flex items-center gap-2 text-sm font-medium text-[var(--color-text)]">
              <input
                type="checkbox"
                checked={classes[key].enabled}
                onChange={(e) => updateClass(key, { enabled: e.target.checked })}
                className="h-4 w-4"
              />
              {t("settings.generator.useClass", { label: t(labelKey).toLowerCase() })}
            </label>
            {classes[key].enabled && (
              <div className="ml-6 mt-2 flex flex-wrap items-center gap-4 text-sm text-[var(--color-text-muted)]">
                <label className="flex items-center gap-1.5">
                  <input
                    type="radio"
                    name={`mode-${key}`}
                    checked={classes[key].mode === "auto"}
                    onChange={() => updateClass(key, { mode: "auto" })}
                  />
                  {t("settings.generator.modeAuto")}
                </label>
                <label className="flex items-center gap-1.5">
                  <input
                    type="radio"
                    name={`mode-${key}`}
                    checked={classes[key].mode === "fixed"}
                    onChange={() => updateClass(key, { mode: "fixed" })}
                  />
                  {t("settings.generator.modeFixed")}
                  <Input
                    type="number"
                    min={0}
                    max={length}
                    value={classes[key].count}
                    disabled={classes[key].mode !== "fixed"}
                    onChange={(e) => updateClass(key, { count: clamp(Number(e.target.value), 0, length) })}
                    className="w-16 py-1"
                  />
                </label>
              </div>
            )}
          </div>
        ))}
      </div>

      {!atLeastOneEnabled && (
        <p className="flex items-center gap-1.5 text-xs text-[var(--color-danger)]">
          <AlertTriangle size={13} /> {t("settings.generator.noClassSelected")}
        </p>
      )}
      {(sumExceedsLength || anyFixedExceedsLength) && (
        <p className="flex items-center gap-1.5 text-xs text-[var(--color-danger)]">
          <AlertTriangle size={13} /> {t("settings.generator.sumExceeds", { length })}
        </p>
      )}
      {sameStartEndTooSmall && (
        <p className="flex items-center gap-1.5 text-xs text-[var(--color-danger)]">
          <AlertTriangle size={13} /> {t("settings.generator.sameStartEndTooSmall")}
        </p>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>{t("settings.generator.startWithLabel")}</Label>
          <select
            value={startType}
            onChange={(e) => setStartType(e.target.value as PasswordCharClass | "none")}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-2 text-sm outline-none"
          >
            <option value="none">{t("settings.generator.noPreference")}</option>
            {CLASS_KEYS.filter((c) => classAvailable(c.key)).map((c) => (
              <option key={c.key} value={c.key}>
                {t(c.labelKey)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <Label>{t("settings.generator.endWithLabel")}</Label>
          <select
            value={endType}
            onChange={(e) => setEndType(e.target.value as PasswordCharClass | "none")}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-2 text-sm outline-none"
          >
            <option value="none">{t("settings.generator.noPreference")}</option>
            {CLASS_KEYS.filter((c) => classAvailable(c.key)).map((c) => (
              <option key={c.key} value={c.key}>
                {t(c.labelKey)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <label className="flex items-center gap-2 text-sm text-[var(--color-text)]">
        <input type="checkbox" checked={avoidSequences} onChange={(e) => setAvoidSequences(e.target.checked)} className="h-4 w-4" />
        {t("settings.generator.avoidSequences")}
      </label>

      <Button variant="primary" onClick={handleGenerate} disabled={!canGenerate} className="w-full">
        <Wand2 size={14} /> {generating ? t("settings.generator.generating") : t("settings.generator.generateButton")}
      </Button>

      {password && (
        <div className="space-y-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-hover)] p-3">
          <p className="select-all break-all text-center font-mono text-sm text-[var(--color-text)]">{password}</p>
          <div className="flex gap-2">
            <Button variant="secondary" size="sm" className="flex-1" onClick={handleGenerate} disabled={generating}>
              <RefreshCw size={13} /> {t("settings.generator.generateAgain")}
            </Button>
            <Button variant="secondary" size="sm" className="flex-1" onClick={() => copySecret(!!password, (secs) => clipboardCommands.copySecret(password ?? "", secs), t("settings.generator.copiedLabel"))}>
              <Copy size={13} /> {t("settings.generator.copyButton")}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
