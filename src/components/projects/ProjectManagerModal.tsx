import { useState } from "react";
import { ArrowDown, ArrowUp, Pencil, Plus, Trash2 } from "lucide-react";
import { Modal } from "../ui/Modal";
import { Avatar } from "../ui/Avatar";
import { Button } from "../ui/Button";
import { ConfirmDialog } from "../ui/ConfirmDialog";
import { ProjectForm } from "./ProjectForm";
import type { ProjectFormValues, ProjectWithRelations, Tag } from "../../types";
import { createProject, deleteProject, reorderProjects, updateProject } from "../../lib/db";
import { useToastStore } from "../../store/useToastStore";
import { useTranslation } from "../../i18n";

interface Props {
  open: boolean;
  onClose: () => void;
  projects: ProjectWithRelations[];
  tags: Tag[];
  onChanged: () => void;
}

export function ProjectManagerModal({ open, onClose, projects, tags, onChanged }: Props) {
  const { t, tc } = useTranslation();
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<ProjectWithRelations | null>(null);
  const [pendingDelete, setPendingDelete] = useState<ProjectWithRelations | null>(null);
  const push = useToastStore((s) => s.push);

  async function handleSubmit(values: ProjectFormValues) {
    if (editing) {
      await updateProject(editing.id, values);
      push(t("projects.toasts.updatedShort"), "success");
    } else {
      await createProject(values);
      push(t("projects.toasts.createdShort"), "success");
    }
    onChanged();
  }

  async function handleDelete() {
    if (!pendingDelete) return;
    await deleteProject(pendingDelete.id);
    setPendingDelete(null);
    onChanged();
    push(t("projects.toasts.deletedShort"), "success");
  }

  async function handleMove(project: ProjectWithRelations, direction: -1 | 1) {
    const index = projects.findIndex((p) => p.id === project.id);
    const target = index + direction;
    if (index === -1 || target < 0 || target >= projects.length) return;
    const reordered = [...projects];
    [reordered[index], reordered[target]] = [reordered[target], reordered[index]];
    await reorderProjects(reordered.map((p) => p.id));
    onChanged();
  }

  return (
    <>
      <Modal open={open} onClose={onClose} title={t("projects.manager.title")} width="md">
        <div className="mb-3 flex justify-end">
          <Button
            variant="primary"
            onClick={() => {
              setEditing(null);
              setFormOpen(true);
            }}
          >
            <Plus size={15} /> {t("projects.manager.newProject")}
          </Button>
        </div>
        <div className="max-h-96 space-y-1 overflow-y-auto">
          {projects.map((project, index) => (
            <div key={project.id} className="flex items-center gap-3 rounded-lg px-2 py-2 hover:bg-[var(--color-surface-hover)]">
              <Avatar imageId={project.avatar_image_id} size={28} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{project.name}</p>
                <p className="truncate text-xs text-[var(--color-text-muted)]">{tc("common.accountsCount", project.accountsCount)}</p>
              </div>
              <button
                type="button"
                onClick={() => handleMove(project, -1)}
                disabled={index === 0}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                title={t("projects.manager.moveUp")}
              >
                <ArrowUp size={14} />
              </button>
              <button
                type="button"
                onClick={() => handleMove(project, 1)}
                disabled={index === projects.length - 1}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                title={t("projects.manager.moveDown")}
              >
                <ArrowDown size={14} />
              </button>
              <button
                type="button"
                onClick={() => {
                  setEditing(project);
                  setFormOpen(true);
                }}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
              >
                <Pencil size={14} />
              </button>
              <button
                type="button"
                onClick={() => setPendingDelete(project)}
                className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-danger)]"
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      </Modal>

      <ProjectForm open={formOpen} onClose={() => setFormOpen(false)} onSubmit={handleSubmit} editingProject={editing} tags={tags} />

      <ConfirmDialog
        open={!!pendingDelete}
        title={t("projects.confirmDeleteTitle")}
        message={t("projects.confirmDeleteMessage", { name: pendingDelete?.name ?? "" })}
        confirmLabel={t("projects.confirmDeleteLabel")}
        danger
        onConfirm={handleDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </>
  );
}
