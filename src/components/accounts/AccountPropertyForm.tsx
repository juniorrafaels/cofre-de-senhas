import { FormEvent, useEffect, useState } from "react";
import { Modal } from "../ui/Modal";
import { Input, Label, Textarea } from "../ui/Input";
import { Button } from "../ui/Button";
import { PROPERTY_TYPES, type PropertyDefinition, type PropertyType } from "../../types";
import { useTranslation } from "../../i18n";
import { propertyTypeLabel } from "../../i18n/enumLabels";
import { translateBackendError } from "../../i18n/backendErrors";

export interface EditingPropertyState {
  name: string;
  type: PropertyType;
  value: string;
  isSensitive: boolean;
}

interface Props {
  open: boolean;
  onClose: () => void;
  onSubmit: (input: { name: string; type: PropertyType; value: string; isSensitive: boolean }) => Promise<void>;
  definitions: PropertyDefinition[];
  editing?: EditingPropertyState | null;
}

export function AccountPropertyForm({ open, onClose, onSubmit, definitions, editing }: Props) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const [type, setType] = useState<PropertyType>("text");
  const [value, setValue] = useState("");
  const [isSensitive, setIsSensitive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) {
      setName(editing?.name ?? "");
      setType(editing?.type ?? "text");
      setValue(editing?.value ?? "");
      setIsSensitive(editing?.isSensitive ?? false);
      setError(null);
    }
  }, [open, editing]);

  function handleSelectExisting(definitionName: string) {
    setName(definitionName);
    const def = definitions.find((d) => d.name === definitionName);
    if (def) setType(def.type);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) {
      setError(t("accounts.propertyForm.nameRequiredError"));
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await onSubmit({ name: name.trim(), type, value, isSensitive });
      onClose();
    } catch (err) {
      setError(translateBackendError(t, err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={editing ? t("accounts.propertyForm.titleEdit") : t("accounts.propertyForm.titleAdd")} width="sm">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <Label>{t("accounts.propertyForm.nameLabel")}</Label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            list="property-definitions"
            autoFocus
            disabled={!!editing}
            placeholder={t("accounts.propertyForm.namePlaceholder")}
          />
          <datalist id="property-definitions">
            {definitions.map((d) => (
              <option key={d.id} value={d.name} />
            ))}
          </datalist>
          {!editing && definitions.length > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {definitions.slice(0, 6).map((d) => (
                <button
                  key={d.id}
                  type="button"
                  onClick={() => handleSelectExisting(d.name)}
                  className="rounded-full bg-[var(--color-surface-hover)] px-2 py-0.5 text-[11px] text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
                >
                  {d.name}
                </button>
              ))}
            </div>
          )}
        </div>

        <div>
          <Label>{t("accounts.propertyForm.typeLabel")}</Label>
          <select
            value={type}
            disabled={!!editing}
            onChange={(e) => setType(e.target.value as PropertyType)}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40 disabled:opacity-60"
          >
            {PROPERTY_TYPES.map((value) => (
              <option key={value} value={value}>
                {propertyTypeLabel(t, value)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <Label>{t("accounts.propertyForm.valueLabel")}</Label>
          {type === "boolean" ? (
            <select
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-[var(--color-accent)]/40"
            >
              <option value="">{t("common.selectPlaceholder")}</option>
              <option value="true">{t("common.yes")}</option>
              <option value="false">{t("common.no")}</option>
            </select>
          ) : type === "longtext" ? (
            <Textarea rows={3} value={value} onChange={(e) => setValue(e.target.value)} />
          ) : (
            <Input
              type={type === "date" ? "date" : type === "number" ? "number" : "text"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          )}
        </div>

        <label className="flex items-center gap-2 text-sm text-[var(--color-text)]">
          <input type="checkbox" checked={isSensitive} onChange={(e) => setIsSensitive(e.target.checked)} className="h-4 w-4 rounded border-[var(--color-border)]" />
          {t("accounts.propertyForm.sensitiveLabel")}
        </label>

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={saving}>
            {saving ? t("common.saving") : editing ? t("common.save") : t("common.add")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
