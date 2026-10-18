import { useCallback, useEffect, useState } from "react";
import { Copy, Eye, EyeOff, Pencil, Plus, Trash2 } from "lucide-react";
import { Button } from "../ui/Button";
import { AccountPropertyForm, type EditingPropertyState } from "./AccountPropertyForm";
import {
  createAccountProperty,
  deleteAccountProperty,
  ensurePropertyDefinition,
  listAccountProperties,
  listPropertyDefinitions,
  logHistory,
  updateAccountProperty,
} from "../../lib/db";
import { propertySecretCommands } from "../../lib/tauri";
import { useCopy, useCopySecret } from "../../lib/useCopy";
import { useToastStore } from "../../store/useToastStore";
import type { AccountPropertyWithDefinition, PropertyDefinition } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

export function AccountPropertiesSection({ accountId }: { accountId: number }) {
  const { t } = useTranslation();
  const [properties, setProperties] = useState<AccountPropertyWithDefinition[]>([]);
  const [definitions, setDefinitions] = useState<PropertyDefinition[]>([]);
  const [formOpen, setFormOpen] = useState(false);
  const [editingProperty, setEditingProperty] = useState<AccountPropertyWithDefinition | null>(null);
  const [editingState, setEditingState] = useState<EditingPropertyState | null>(null);
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const push = useToastStore((s) => s.push);
  const copy = useCopy();
  const copySecret = useCopySecret();

  const refresh = useCallback(async () => {
    const [props, defs] = await Promise.all([listAccountProperties(accountId), listPropertyDefinitions()]);
    setProperties(props);
    setDefinitions(defs);
  }, [accountId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Fase 4 (SECURITY_AUDIT_PHASE_4.md): o valor sempre chega em texto puro — é o Rust
  // (`create_account_property`/`update_account_property`) quem cifra internamente quando
  // `isSensitive`. Não existe mais `secretCommands.encrypt` para chamar aqui.
  async function handleSubmit(input: { name: string; type: PropertyDefinition["type"]; value: string; isSensitive: boolean }) {
    if (editingProperty) {
      await updateAccountProperty(accountId, editingProperty.id, input.value, input.isSensitive);
      await logHistory(accountId, "property_changed", editingProperty.name);
      push(t("accounts.properties.updatedToast"), "success");
    } else {
      const definitionId = await ensurePropertyDefinition(input.name, input.type);
      await createAccountProperty(accountId, definitionId, input.value, input.isSensitive);
      await logHistory(accountId, "property_added", input.name);
      push(t("accounts.properties.addedToast"), "success");
    }
    setRevealed({});
    await refresh();
  }

  async function handleDelete(prop: AccountPropertyWithDefinition) {
    await deleteAccountProperty(accountId, prop.id);
    await logHistory(accountId, "property_removed", prop.name);
    await refresh();
    push(t("accounts.properties.removedToast"), "success");
  }

  async function handleEdit(prop: AccountPropertyWithDefinition) {
    let plaintext = "";
    if (prop.is_sensitive) {
      if (prop.has_value) {
        try {
          plaintext = await propertySecretCommands.reveal(accountId, prop.id);
        } catch (err) {
          push(t("accounts.properties.revealFailed", { error: translateBackendError(t, err) }), "error");
        }
      }
    } else {
      plaintext = prop.value ?? "";
    }
    setEditingProperty(prop);
    setEditingState({ name: prop.name, type: prop.type, value: plaintext, isSensitive: !!prop.is_sensitive });
    setFormOpen(true);
  }

  function handleAddNew() {
    setEditingProperty(null);
    setEditingState(null);
    setFormOpen(true);
  }

  async function handleReveal(prop: AccountPropertyWithDefinition) {
    if (!prop.has_value) return;
    try {
      const plaintext = prop.is_sensitive ? await propertySecretCommands.reveal(accountId, prop.id) : prop.value ?? "";
      setRevealed((r) => ({ ...r, [prop.id]: plaintext }));
    } catch (err) {
      push(t("accounts.properties.revealFailed", { error: translateBackendError(t, err) }), "error");
    }
  }

  async function handleCopy(prop: AccountPropertyWithDefinition) {
    if (prop.is_sensitive) {
      // Decifra e copia inteiramente no backend — o plaintext não passa pelo frontend aqui.
      await copySecret(prop.has_value, (seconds) => propertySecretCommands.copy(accountId, prop.id, seconds), prop.name);
    } else {
      await copy(prop.value, prop.name);
    }
  }

  return (
    <div className="space-y-2">
      {properties.length === 0 && <p className="text-sm text-[var(--color-text-muted)]">{t("accounts.properties.empty")}</p>}
      {properties.map((prop) => (
        <div key={prop.id} className="rounded-lg border border-[var(--color-border)] p-2.5">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-[var(--color-text-muted)]">{prop.name}</p>
            <div className="flex items-center gap-0.5">
              <button onClick={() => handleEdit(prop)} className="rounded-md p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
                <Pencil size={12} />
              </button>
              <button onClick={() => handleDelete(prop)} className="rounded-md p-1 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-danger)]">
                <Trash2 size={12} />
              </button>
            </div>
          </div>
          <div className="mt-1 flex items-center gap-1.5">
            <p className="flex-1 truncate text-sm text-[var(--color-text)]">
              {prop.is_sensitive ? (revealed[prop.id] ?? "••••••••••") : prop.value || "—"}
            </p>
            {prop.is_sensitive && (
              <button onClick={() => handleReveal(prop)} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
                {revealed[prop.id] ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            )}
            <button onClick={() => handleCopy(prop)} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
              <Copy size={13} />
            </button>
          </div>
        </div>
      ))}

      <Button variant="secondary" size="sm" onClick={handleAddNew}>
        <Plus size={13} /> {t("accounts.properties.add")}
      </Button>

      <AccountPropertyForm
        open={formOpen}
        onClose={() => setFormOpen(false)}
        onSubmit={handleSubmit}
        definitions={definitions}
        editing={editingState}
      />
    </div>
  );
}
