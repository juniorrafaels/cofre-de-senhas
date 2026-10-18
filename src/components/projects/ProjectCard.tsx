import { Star } from "lucide-react";
import type { ProjectWithRelations } from "../../types";
import { Avatar } from "../ui/Avatar";
import { useTranslation } from "../../i18n";

interface Props {
  project: ProjectWithRelations;
  onOpen: () => void;
  onToggleFavorite: () => void;
}

export function ProjectCard({ project, onOpen, onToggleFavorite }: Props) {
  const { tc } = useTranslation();
  return (
    <div
      onClick={onOpen}
      className="group cursor-pointer rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 transition-shadow hover:shadow-md"
      style={project.color ? { borderTopColor: project.color, borderTopWidth: 3 } : undefined}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2.5">
          <Avatar imageId={project.avatar_image_id} size={40} />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-[var(--color-text)]">{project.name}</p>
            <p className="truncate text-xs text-[var(--color-text-muted)]">{tc("common.accountsCount", project.accountsCount)}</p>
          </div>
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggleFavorite();
          }}
          className="shrink-0 text-[var(--color-text-muted)] hover:text-amber-400"
        >
          <Star size={16} fill={project.favorite ? "currentColor" : "none"} className={project.favorite ? "text-amber-400" : ""} />
        </button>
      </div>

      {project.platformNames.length > 0 && (
        <p className="mt-3 truncate text-xs text-[var(--color-text-muted)]">{project.platformNames.join(" · ")}</p>
      )}

      {project.tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {project.tags.slice(0, 3).map((tag) => (
            <span key={tag.id} className="rounded-full bg-[var(--color-surface-hover)] px-2 py-0.5 text-[11px] text-[var(--color-text-muted)]">
              {tag.name}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
