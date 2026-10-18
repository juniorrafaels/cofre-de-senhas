import { useCallback, useEffect, useState } from "react";
import { Check, Pencil, Plus, Search, Tag as TagIcon, Trash2, X } from "lucide-react";
import { Button } from "../ui/Button";
import { Input } from "../ui/Input";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { createTag, deleteTag, listTagsWithUsage, renameTag, type TagWithUsage } from "../../lib/db";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";

export function TagsManagerSection({ onChanged }: { onChanged: () => void }) {
  const { t } = useTranslation();
  const [tags, setTags] = useState<TagWithUsage[]>([]);
  const [search, setSearch] = useState("");
  const [newTagName, setNewTagName] = useState("");
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editingName, setEditingName] = useState("");
  const [pendingDelete, setPendingDelete] = useState<TagWithUsage | null>(null);
  const push = useToastStore((s) => s.push);

  const refresh = useCallback(async () => {
    setTags(await listTagsWithUsage());
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleCreate() {
    if (!newTagName.trim()) return;
    await createTag(newTagName);
    setNewTagName("");
    await refresh();
    onChanged();
    push(t("settings.tags.createdToast"), "success");
  }

  function startEdit(tag: TagWithUsage) {
    setEditingId(tag.id);
    setEditingName(tag.name);
  }

  async function handleSaveEdit() {
    if (editingId === null || !editingName.trim()) return;
    await renameTag(editingId, editingName);
    setEditingId(null);
    await refresh();
    onChanged();
    push(t("settings.tags.renamedToast"), "success");
  }

  async function handleDelete() {
    if (!pendingDelete) return;
    await deleteTag(pendingDelete.id);
    setPendingDelete(null);
    await refresh();
    onChanged();
    push(t("settings.tags.deletedToast"), "success");
  }

  const filtered = tags.filter((t) => t.name.includes(search.trim().toLowerCase()));

  return (
    <div className="space-y-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-center gap-2 text-sm font-semibold text-[var(--color-text)]">
        <TagIcon size={15} /> {t("settings.tags.title")}
      </div>

      <div className="relative">
        <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]" />
        <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("settings.tags.searchPlaceholder")} className="pl-8" />
      </div>

      <div className="space-y-1">
        {filtered.map((tag) => (
          <div key={tag.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-[var(--color-surface-hover)]">
            {editingId === tag.id ? (
              <>
                <Input value={editingName} onChange={(e) => setEditingName(e.target.value)} autoFocus className="h-8 flex-1" />
                <button onClick={handleSaveEdit} className="rounded-md p-1.5 text-[var(--color-success)] hover:bg-[var(--color-surface-hover)]">
                  <Check size={14} />
                </button>
                <button onClick={() => setEditingId(null)} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
                  <X size={14} />
                </button>
              </>
            ) : (
              <>
                <span className="flex-1 truncate text-sm">{tag.name}</span>
                <span className="text-xs text-[var(--color-text-muted)]">
                  {tag.accountsCount === 1 ? t("common.accountsCount_one", { count: 1 }) : t("common.accountsCount_other", { count: tag.accountsCount })}
                  {tag.projectsCount > 0 &&
                    ` · ${tag.projectsCount === 1 ? t("common.projectsCount_one", { count: 1 }) : t("common.projectsCount_other", { count: tag.projectsCount })}`}
                </span>
                <button onClick={() => startEdit(tag)} className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]">
                  <Pencil size={13} />
                </button>
                <button
                  onClick={() => setPendingDelete(tag)}
                  className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-danger)]"
                >
                  <Trash2 size={13} />
                </button>
              </>
            )}
          </div>
        ))}
        {filtered.length === 0 && <p className="py-2 text-sm text-[var(--color-text-muted)]">{t("settings.tags.noneFound")}</p>}
      </div>

      <div className="flex gap-1.5">
        <Input value={newTagName} onChange={(e) => setNewTagName(e.target.value)} placeholder={t("settings.tags.newTagPlaceholder")} onKeyDown={(e) => e.key === "Enter" && handleCreate()} />
        <Button variant="secondary" onClick={handleCreate}>
          <Plus size={14} /> {t("settings.tags.newTagButton")}
        </Button>
      </div>

      <ConfirmDialog
        open={!!pendingDelete}
        title={t("settings.tags.deleteTitle")}
        message={
          pendingDelete && (pendingDelete.accountsCount > 0 || pendingDelete.projectsCount > 0)
            ? t("settings.tags.deleteConfirmInUse", { name: pendingDelete.name, accounts: pendingDelete.accountsCount, projects: pendingDelete.projectsCount })
            : t("settings.tags.deleteConfirmSimple", { name: pendingDelete?.name ?? "" })
        }
        confirmLabel={t("settings.tags.deleteButton")}
        danger
        onConfirm={handleDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  );
}
