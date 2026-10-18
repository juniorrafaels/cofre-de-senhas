import { FormEvent, useEffect, useState } from "react";
import { ImagePlus, X } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Input, Label } from "../ui/Input";
import { Button } from "../ui/Button";
import { PlatformIcon } from "../ui/PlatformIcon";
import { AvatarPicker } from "../accounts/AvatarPicker";
import type { Platform } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

export interface PlatformFormValues {
  name: string;
  icon: string;
  login_url: string;
  website_url: string;
  logo_image_id: number | null;
}

const ICON_OPTIONS = ["📸", "📘", "▶️", "📧", "🎵", "🐦", "🎮", "✈️", "💼", "🌐", "🔒", "💬", "🛒", "🎬", "📁"];

interface Props {
  open: boolean;
  onClose: () => void;
  onSubmit: (values: PlatformFormValues) => Promise<void>;
  editingPlatform: Platform | null;
}

function emptyValues(): PlatformFormValues {
  return { name: "", icon: "🌐", login_url: "", website_url: "", logo_image_id: null };
}

export function PlatformForm({ open, onClose, onSubmit, editingPlatform }: Props) {
  const { t } = useTranslation();
  const [values, setValues] = useState<PlatformFormValues>(emptyValues());
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [logoPickerOpen, setLogoPickerOpen] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (editingPlatform) {
      setValues({
        name: editingPlatform.name,
        icon: editingPlatform.icon ?? "🌐",
        login_url: editingPlatform.login_url ?? "",
        website_url: editingPlatform.website_url ?? "",
        logo_image_id: editingPlatform.logo_image_id,
      });
    } else {
      setValues(emptyValues());
    }
    setError(null);
  }, [open, editingPlatform]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!values.name.trim()) {
      setError(t("platforms.form.nameRequiredError"));
      return;
    }
    setSaving(true);
    try {
      await onSubmit(values);
      onClose();
    } catch (err) {
      setError(translateBackendError(t, err));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={editingPlatform ? t("platforms.form.titleEdit") : t("platforms.form.titleNew")} width="sm">
      <form onSubmit={handleSubmit} className="space-y-3">
        <div>
          <Label>{t("platforms.form.nameLabel")}</Label>
          <Input value={values.name} onChange={(e) => setValues((v) => ({ ...v, name: e.target.value }))} autoFocus />
        </div>

        <div>
          <Label>{t("platforms.form.logoLabel")}</Label>
          <div className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--color-border)]">
              <PlatformIcon icon={values.icon} logoImageId={values.logo_image_id} size={20} />
            </div>
            <Button type="button" variant="secondary" size="sm" onClick={() => setLogoPickerOpen(true)}>
              <ImagePlus size={13} /> {t("platforms.form.chooseLogo")}
            </Button>
            {values.logo_image_id && (
              <button
                type="button"
                onClick={() => setValues((v) => ({ ...v, logo_image_id: null }))}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
                title={t("platforms.form.removeLogoTitle")}
              >
                <X size={14} />
              </button>
            )}
          </div>
        </div>

        <div>
          <Label>{t("platforms.form.iconLabel")}</Label>
          <div className="flex flex-wrap gap-1.5">
            {ICON_OPTIONS.map((icon) => (
              <button
                key={icon}
                type="button"
                onClick={() => setValues((v) => ({ ...v, icon }))}
                className={`flex h-9 w-9 items-center justify-center rounded-lg border text-base transition-colors ${
                  values.icon === icon
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                    : "border-[var(--color-border)] hover:bg-[var(--color-surface-hover)]"
                }`}
              >
                {icon}
              </button>
            ))}
          </div>
        </div>
        <div>
          <Label>{t("platforms.form.loginUrlLabel")}</Label>
          <Input value={values.login_url} onChange={(e) => setValues((v) => ({ ...v, login_url: e.target.value }))} placeholder="https://..." />
        </div>
        <div>
          <Label>{t("platforms.form.websiteUrlLabel")}</Label>
          <Input value={values.website_url} onChange={(e) => setValues((v) => ({ ...v, website_url: e.target.value }))} placeholder="https://..." />
        </div>

        {error && <p className="text-sm text-[var(--color-danger)]">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={saving}>
            {saving ? t("common.saving") : t("common.save")}
          </Button>
        </div>
      </form>

      <AvatarPicker
        open={logoPickerOpen}
        onClose={() => setLogoPickerOpen(false)}
        currentImageId={values.logo_image_id}
        onSelect={(imageId) => setValues((v) => ({ ...v, logo_image_id: imageId }))}
      />
    </Modal>
  );
}
