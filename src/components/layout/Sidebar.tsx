import { Archive, FolderKanban, LayoutGrid, Lock, Settings, ShieldCheck, Star, Trash2 } from "lucide-react";
import clsx from "clsx";
import type { Platform, ViewState } from "../../types";
import { PlatformIcon } from "../ui/PlatformIcon";
import { useTranslation } from "../../i18n";

interface Props {
  view: ViewState;
  onNavigate: (view: ViewState) => void;
  platforms: Platform[];
  countsByPlatform: Record<number, number>;
  favoritesCount: number;
  projectsCount: number;
  archivedCount: number;
  trashCount: number;
  onLock: () => void;
}

function NavItem({
  active,
  icon,
  label,
  count,
  onClick,
}: {
  active: boolean;
  icon: React.ReactNode;
  label: string;
  count?: number;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
        active
          ? "bg-[var(--color-accent)]/12 text-[var(--color-accent)] font-medium"
          : "text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]",
      )}
    >
      <span className="shrink-0">{icon}</span>
      <span className="flex-1 truncate text-left">{label}</span>
      {typeof count === "number" && (
        <span className="rounded-full bg-[var(--color-surface-hover)] px-2 py-0.5 text-xs text-[var(--color-text-muted)]">
          {count}
        </span>
      )}
    </button>
  );
}

export function Sidebar({
  view,
  onNavigate,
  platforms,
  countsByPlatform,
  favoritesCount,
  projectsCount,
  archivedCount,
  trashCount,
  onLock,
}: Props) {
  const { t } = useTranslation();
  return (
    <aside className="flex h-full w-64 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] p-3">
      <div className="mb-4 flex items-center gap-2 px-2 pt-1.5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--color-accent)]/15 text-[var(--color-accent)]">
          <ShieldCheck size={17} />
        </div>
        <span className="text-sm font-semibold">{t("layout.vaultTitle")}</span>
      </div>

      <nav className="flex flex-col gap-0.5">
        <NavItem
          active={view.type === "dashboard"}
          icon={<LayoutGrid size={16} />}
          label={t("layout.nav.dashboard")}
          onClick={() => onNavigate({ type: "dashboard" })}
        />
        <NavItem
          active={view.type === "favorites"}
          icon={<Star size={16} />}
          label={t("layout.nav.favorites")}
          count={favoritesCount}
          onClick={() => onNavigate({ type: "favorites" })}
        />
        <NavItem
          active={view.type === "projects" || view.type === "project"}
          icon={<FolderKanban size={16} />}
          label={t("layout.nav.projects")}
          count={projectsCount}
          onClick={() => onNavigate({ type: "projects" })}
        />
      </nav>

      <div className="mt-5 px-2 text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
        {t("layout.nav.platformsHeading")}
      </div>
      <nav className="mt-1.5 flex flex-1 flex-col gap-0.5 overflow-y-auto">
        {platforms.map((platform) => (
          <NavItem
            key={platform.id}
            active={view.type === "platform" && view.platformId === platform.id}
            icon={<PlatformIcon icon={platform.icon} logoImageId={platform.logo_image_id} size={16} />}
            label={platform.name}
            count={countsByPlatform[platform.id] ?? 0}
            onClick={() => onNavigate({ type: "platform", platformId: platform.id })}
          />
        ))}
      </nav>

      <div className="mt-3 flex flex-col gap-0.5 border-t border-[var(--color-border)] pt-3">
        <NavItem
          active={view.type === "archived"}
          icon={<Archive size={16} />}
          label={t("layout.nav.archived")}
          count={archivedCount}
          onClick={() => onNavigate({ type: "archived" })}
        />
        <NavItem
          active={view.type === "trash"}
          icon={<Trash2 size={16} />}
          label={t("layout.nav.trash")}
          count={trashCount}
          onClick={() => onNavigate({ type: "trash" })}
        />
        <NavItem
          active={view.type === "settings"}
          icon={<Settings size={16} />}
          label={t("layout.nav.settings")}
          onClick={() => onNavigate({ type: "settings" })}
        />
        <NavItem active={false} icon={<Lock size={16} />} label={t("layout.nav.lock")} onClick={onLock} />
      </div>
    </aside>
  );
}
