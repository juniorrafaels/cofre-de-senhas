import { useState } from "react";
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2 } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { PlatformIcon } from "../ui/PlatformIcon";
import { PlatformForm, type PlatformFormValues } from "./PlatformForm";
import type { Platform } from "../../types";
import { createPlatform, deletePlatform, reassignAccountsPlatform, reorderPlatforms, updatePlatform } from "../../lib/db";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";

interface Props {
  open: boolean;
  onClose: () => void;
  platforms: Platform[];
  countsByPlatform: Record<number, number>;
  onChanged: () => void;
}

function DeletePlatformDialog({
  platform,
  platforms,
  linkedCount,
  onCancel,
  onConfirm,
}: {
  platform: Platform;
  platforms: Platform[];
  linkedCount: number;
  onCancel: () => void;
  onConfirm: (reassignTo: number | null) => void;
}) {
  const { t, tc } = useTranslation();
  const [reassignTo, setReassignTo] = useState<string>("");
  const otherPlatforms = platforms.filter((p) => p.id !== platform.id);

  return (
    <Modal open onClose={onCancel} title={t("platforms.deleteDialog.title")} width="sm">
      {linkedCount > 0 ? (
        <>
          <p className="text-sm text-[var(--color-text)]">{tc("platforms.deleteDialog.linkedWarning", linkedCount)}</p>
          <p className="mt-1 text-sm text-[var(--color-text-muted)]">{t("platforms.deleteDialog.reassignPrompt", { name: platform.name })}</p>
          <div className="mt-3">
            <select
              value={reassignTo}
              onChange={(e) => setReassignTo(e.target.value)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none"
            >
              <option value="">{t("platforms.deleteDialog.noPlatformOption")}</option>
              {otherPlatforms.map((p) => (
                <option key={p.id} value={p.id}>
                  {t("platforms.deleteDialog.moveToOption", { name: p.name })}
                </option>
              ))}
            </select>
          </div>
        </>
      ) : (
        <p className="text-sm text-[var(--color-text-muted)]">{t("platforms.deleteDialog.confirmSimple", { name: platform.name })}</p>
      )}

      <div className="mt-5 flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          {t("common.cancel")}
        </Button>
        <Button variant="danger" onClick={() => onConfirm(reassignTo ? Number(reassignTo) : null)}>
          {t("common.delete")}
        </Button>
      </div>
    </Modal>
  );
}

export function PlatformManagerModal({ open, onClose, platforms, countsByPlatform, onChanged }: Props) {
  const { t, tc } = useTranslation();
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Platform | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Platform | null>(null);
  const push = useToastStore((s) => s.push);

  async function handleSubmit(values: PlatformFormValues) {
    if (editing) {
      await updatePlatform(editing.id, values);
      push(t("platforms.toasts.updated"), "success");
    } else {
      await createPlatform(values);
      push(t("platforms.toasts.created"), "success");
    }
    onChanged();
  }

  async function handleDelete(reassignTo: number | null) {
    if (!pendingDelete) return;
    if ((countsByPlatform[pendingDelete.id] ?? 0) > 0) {
      await reassignAccountsPlatform(pendingDelete.id, reassignTo);
    }
    await deletePlatform(pendingDelete.id);
    setPendingDelete(null);
    onChanged();
    push(t("platforms.toasts.deleted"), "success");
  }

  async function handleMove(platform: Platform, direction: -1 | 1) {
    const index = platforms.findIndex((p) => p.id === platform.id);
    const target = index + direction;
    if (index === -1 || target < 0 || target >= platforms.length) return;
    const reordered = [...platforms];
    [reordered[index], reordered[target]] = [reordered[target], reordered[index]];
    await reorderPlatforms(reordered.map((p) => p.id));
    onChanged();
  }

  return (
    <>
      <Modal open={open} onClose={onClose} title={t("platforms.manageTitle")} width="md">
        <div className="mb-3 flex justify-end">
          <Button
            variant="primary"
            onClick={() => {
              setEditing(null);
              setFormOpen(true);
            }}
          >
            <Plus size={15} /> {t("platforms.newPlatform")}
          </Button>
        </div>
        <div className="max-h-96 space-y-1 overflow-y-auto">
          {platforms.map((platform, index) => (
            <div key={platform.id} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-[var(--color-surface-hover)]">
              <PlatformIcon icon={platform.icon} logoImageId={platform.logo_image_id} size={17} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{platform.name}</p>
                <p className="truncate text-xs text-[var(--color-text-muted)]">{tc("common.accountsCount", countsByPlatform[platform.id] ?? 0)}</p>
              </div>
              <button
                type="button"
                onClick={() => handleMove(platform, -1)}
                disabled={index === 0}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                title={t("platforms.moveUp")}
              >
                <ArrowUp size={14} />
              </button>
              <button
                type="button"
                onClick={() => handleMove(platform, 1)}
                disabled={index === platforms.length - 1}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                title={t("platforms.moveDown")}
              >
                <ArrowDown size={14} />
              </button>
              <button
                type="button"
                onClick={() => {
                  setEditing(platform);
                  setFormOpen(true);
                }}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
              >
                <Pencil size={14} />
              </button>
              <button
                type="button"
                onClick={() => setPendingDelete(platform)}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-danger)]"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      </Modal>

      <PlatformForm open={formOpen} onClose={() => setFormOpen(false)} onSubmit={handleSubmit} editingPlatform={editing} />

      {pendingDelete && (
        <DeletePlatformDialog
          platform={pendingDelete}
          platforms={platforms}
          linkedCount={countsByPlatform[pendingDelete.id] ?? 0}
          onCancel={() => setPendingDelete(null)}
          onConfirm={handleDelete}
        />
      )}
    </>
  );
}
