import { useEffect, useState } from "react";
import { Check, Pencil, Plus, Search, Trash2, X } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { resolveImageSrc, pickAndImportImage, deleteImageFile } from "../../lib/images";
import { listImages, deleteImageRecord, countAccountsUsingImage, countProjectsUsingImage, countPlatformsUsingImage, updateImageName } from "../../lib/db";
import { useToastStore } from "../../store/useToastStore";
import type { ImageRecord } from "../../types";
import { useTranslation } from "../../i18n";
import { translateBackendError } from "../../i18n/backendErrors";

interface Props {
  open: boolean;
  onClose: () => void;
  onSelect: (imageId: number | null) => void;
  currentImageId: number | null;
}

interface Usage {
  accounts: number;
  projects: number;
  platforms: number;
}

function LibraryThumb({
  image,
  selected,
  usage,
  onSelect,
  onDelete,
  onRename,
}: {
  image: ImageRecord;
  selected: boolean;
  usage: Usage;
  onSelect: () => void;
  onDelete: () => void;
  onRename: (name: string) => void;
}) {
  const { t } = useTranslation();
  const [src, setSrc] = useState<string | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(image.name ?? "");
  const totalUsage = usage.accounts + usage.projects + usage.platforms;

  useEffect(() => {
    resolveImageSrc(image.filename).then(setSrc);
  }, [image.filename]);

  return (
    <div className="space-y-1">
      <div
        onClick={onSelect}
        className={`group relative aspect-square cursor-pointer overflow-hidden rounded-lg border-2 ${
          selected ? "border-[var(--color-accent)]" : "border-transparent"
        }`}
      >
        {src && <img src={src} alt="" className="h-full w-full object-cover" />}
        {totalUsage > 0 && (
          <span className="absolute bottom-1 left-1 rounded-full bg-black/60 px-1.5 py-0.5 text-[10px] text-white">{totalUsage}x</span>
        )}
        <button
          onClick={(e) => {
            e.stopPropagation();
            setRenaming(true);
          }}
          className="absolute right-1 top-1 rounded-full bg-black/60 p-1 text-white opacity-0 transition-opacity group-hover:opacity-100"
        >
          <Pencil size={11} />
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
          className="absolute right-1 top-7 rounded-full bg-black/60 p-1 text-white opacity-0 transition-opacity group-hover:opacity-100"
        >
          <Trash2 size={11} />
        </button>
      </div>
      {renaming ? (
        <div className="flex items-center gap-1">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
            className="w-full rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-1 py-0.5 text-[11px] outline-none"
          />
          <button
            onClick={() => {
              onRename(name);
              setRenaming(false);
            }}
            className="text-[var(--color-success)]"
          >
            <Check size={12} />
          </button>
        </div>
      ) : (
        <p className="truncate text-center text-[10px] text-[var(--color-text-muted)]">{image.name || t("accounts.avatarPicker.noName")}</p>
      )}
    </div>
  );
}

export function AvatarPicker({ open, onClose, onSelect, currentImageId }: Props) {
  const { t, tc } = useTranslation();
  const [images, setImages] = useState<ImageRecord[]>([]);
  const [search, setSearch] = useState("");
  const [blockedDelete, setBlockedDelete] = useState<{ image: ImageRecord; usage: Usage } | null>(null);
  const [importing, setImporting] = useState(false);
  const [usage, setUsage] = useState<Record<number, Usage>>({});
  const push = useToastStore((s) => s.push);

  async function refresh(query?: string) {
    const list = await listImages(query);
    setImages(list);
    const entries = await Promise.all(
      list.map(async (img) => {
        const [accounts, projects, platforms] = await Promise.all([
          countAccountsUsingImage(img.id),
          countProjectsUsingImage(img.id),
          countPlatformsUsingImage(img.id),
        ]);
        return [img.id, { accounts, projects, platforms }] as const;
      }),
    );
    setUsage(Object.fromEntries(entries));
  }

  useEffect(() => {
    if (open) refresh(search);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const timeout = setTimeout(() => refresh(search), 200);
    return () => clearTimeout(timeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  async function handleImport() {
    setImporting(true);
    try {
      const image = await pickAndImportImage();
      if (image) {
        await refresh(search);
        onSelect(image.id);
        onClose();
      }
    } catch (err) {
      push(t("accounts.avatarPicker.importFailed", { error: translateBackendError(t, err) }), "error");
    } finally {
      setImporting(false);
    }
  }

  function handleRequestDelete(image: ImageRecord) {
    const u = usage[image.id] ?? { accounts: 0, projects: 0, platforms: 0 };
    setBlockedDelete({ image, usage: u });
  }

  async function handleConfirmDelete() {
    if (!blockedDelete) return;
    await deleteImageRecord(blockedDelete.image.id);
    await deleteImageFile(blockedDelete.image.filename);
    setBlockedDelete(null);
    await refresh(search);
    push(t("accounts.avatarPicker.removedToast"), "success");
  }

  async function handleRename(image: ImageRecord, name: string) {
    await updateImageName(image.id, name);
    await refresh(search);
  }

  const blockedTotal = blockedDelete ? blockedDelete.usage.accounts + blockedDelete.usage.projects + blockedDelete.usage.platforms : 0;

  return (
    <>
      <Modal open={open} onClose={onClose} title={t("accounts.avatarPicker.title")} width="md">
        <div className="mb-3 space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="relative flex-1">
              <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
              <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("accounts.avatarPicker.searchPlaceholder")} className="pl-8" />
            </div>
            {currentImageId && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  onSelect(null);
                  onClose();
                }}
              >
                <X size={13} /> {t("accounts.avatarPicker.remove")}
              </Button>
            )}
            <Button size="sm" variant="primary" onClick={handleImport} disabled={importing}>
              <Plus size={13} /> {importing ? t("accounts.avatarPicker.importing") : t("accounts.avatarPicker.add")}
            </Button>
          </div>
        </div>

        {images.length === 0 ? (
          <p className="py-10 text-center text-sm text-[var(--color-text-muted)]">{t("accounts.avatarPicker.emptyLibrary")}</p>
        ) : (
          <div className="grid max-h-96 grid-cols-5 gap-3 overflow-y-auto">
            {images.map((image) => (
              <LibraryThumb
                key={image.id}
                image={image}
                selected={image.id === currentImageId}
                usage={usage[image.id] ?? { accounts: 0, projects: 0, platforms: 0 }}
                onSelect={() => {
                  onSelect(image.id);
                  onClose();
                }}
                onDelete={() => handleRequestDelete(image)}
                onRename={(name) => handleRename(image, name)}
              />
            ))}
          </div>
        )}
      </Modal>

      <Modal open={!!blockedDelete} onClose={() => setBlockedDelete(null)} title={t("accounts.avatarPicker.deleteTitle")} width="sm">
        {blockedTotal > 0 ? (
          <>
            <p className="text-sm text-[var(--color-text)]">{t("accounts.avatarPicker.usedByIntro")}</p>
            <ul className="mt-2 space-y-1 text-sm text-[var(--color-text-muted)]">
              {blockedDelete!.usage.accounts > 0 && <li>{tc("accounts.avatarPicker.usedByAccounts", blockedDelete!.usage.accounts)}</li>}
              {blockedDelete!.usage.projects > 0 && <li>{tc("accounts.avatarPicker.usedByProjects", blockedDelete!.usage.projects)}</li>}
              {blockedDelete!.usage.platforms > 0 && <li>{tc("accounts.avatarPicker.usedByPlatforms", blockedDelete!.usage.platforms)}</li>}
            </ul>
            <p className="mt-2 text-xs text-[var(--color-text-muted)]">{t("accounts.avatarPicker.replaceBeforeDelete")}</p>
            <div className="mt-4 flex justify-end">
              <Button variant="secondary" onClick={() => setBlockedDelete(null)}>
                {t("common.understood")}
              </Button>
            </div>
          </>
        ) : (
          <>
            <p className="text-sm text-[var(--color-text-muted)]">{t("accounts.avatarPicker.confirmRemove")}</p>
            <div className="mt-4 flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setBlockedDelete(null)}>
                {t("common.cancel")}
              </Button>
              <Button variant="danger" onClick={handleConfirmDelete}>
                {t("common.remove")}
              </Button>
            </div>
          </>
        )}
      </Modal>
    </>
  );
}
