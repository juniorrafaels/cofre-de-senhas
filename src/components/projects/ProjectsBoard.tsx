import { Plus, Star } from "lucide-react";
import type { ProjectWithRelations, ViewMode } from "../../types";
import { ProjectCard } from "./ProjectCard";
import { Avatar } from "../ui/Avatar";
import { EmptyState } from "../ui/EmptyState";
import { Button } from "../ui/Button";
import { useSettingsStore } from "../../store/useSettingsStore";
import { useTranslation } from "../../i18n";

interface Props {
  projects: ProjectWithRelations[];
  viewMode: ViewMode;
  onOpen: (project: ProjectWithRelations) => void;
  onToggleFavorite: (project: ProjectWithRelations) => void;
  onAddProject: () => void;
}

export function ProjectsBoard({ projects, viewMode, onOpen, onToggleFavorite, onAddProject }: Props) {
  const listScale = useSettingsStore((s) => s.listScale);
  const { t } = useTranslation();

  if (projects.length === 0) {
    return (
      <EmptyState
        title={t("projects.board.emptyTitle")}
        description={t("projects.board.emptyDescription")}
        action={
          <Button variant="primary" onClick={onAddProject}>
            <Plus size={15} /> {t("projects.board.newProject")}
          </Button>
        }
      />
    );
  }

  if (viewMode === "list") {
    return (
      <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]" style={{ zoom: listScale / 100 }}>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-muted)]">
              <th className="px-4 py-2.5 font-medium">{t("projects.board.headerProject")}</th>
              <th className="px-4 py-2.5 font-medium">{t("projects.board.headerPlatforms")}</th>
              <th className="px-4 py-2.5 font-medium">{t("projects.board.headerAccounts")}</th>
              <th className="px-4 py-2.5 font-medium text-right">{t("projects.board.headerFavorite")}</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((project) => (
              <tr
                key={project.id}
                onClick={() => onOpen(project)}
                className="cursor-pointer border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface-hover)]"
              >
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2.5">
                    <Avatar imageId={project.avatar_image_id} size={28} />
                    <span className="font-medium text-[var(--color-text)]">{project.name}</span>
                  </div>
                </td>
                <td className="px-4 py-2.5 text-[var(--color-text-muted)]">{project.platformNames.join(" · ") || t("common.dash")}</td>
                <td className="px-4 py-2.5 text-[var(--color-text-muted)]">{project.accountsCount}</td>
                <td className="px-4 py-2.5 text-right">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleFavorite(project);
                    }}
                    className="rounded-md p-1.5 text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-amber-400"
                  >
                    <Star size={14} fill={project.favorite ? "currentColor" : "none"} className={project.favorite ? "text-amber-400" : ""} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4" style={{ zoom: listScale / 100 }}>
      {projects.map((project) => (
        <ProjectCard key={project.id} project={project} onOpen={() => onOpen(project)} onToggleFavorite={() => onToggleFavorite(project)} />
      ))}
    </div>
  );
}
