import { useEffect, useMemo, useState } from "react";
import { Sidebar } from "./components/layout/Sidebar";
import { TopBar } from "./components/layout/TopBar";
import { CategoryCard } from "./components/layout/CategoryCard";
import { AccountsBoard } from "./components/accounts/AccountsBoard";
import { AccountForm, type SensitiveField } from "./components/accounts/AccountForm";
import { AccountDetailModal } from "./components/accounts/AccountDetailModal";
import { PlatformManagerModal } from "./components/platforms/PlatformManagerModal";
import { PlatformForm, type PlatformFormValues } from "./components/platforms/PlatformForm";
import { SettingsView } from "./components/settings/SettingsView";
import { CreateMasterPassword } from "./components/vault/CreateMasterPassword";
import { UnlockScreen } from "./components/vault/UnlockScreen";
import { ConfirmDialog } from "./components/ui/ConfirmDialog";
import { ToastContainer } from "./components/ui/Toast";
import { ProjectsBoard } from "./components/projects/ProjectsBoard";
import { ProjectForm } from "./components/projects/ProjectForm";
import { ProjectDetailView } from "./components/projects/ProjectDetailView";
import { TrashView } from "./components/accounts/TrashView";
import { useVaultStore } from "./store/useVaultStore";
import { useSettingsStore } from "./store/useSettingsStore";
import { useToastStore } from "./store/useToastStore";
import { useLibrary } from "./lib/useLibrary";
import { useAutoLock } from "./lib/useAutoLock";
import { matchesSearch } from "./lib/filter";
import { useTranslation } from "./i18n";
import {
  archiveAccount,
  createAccount,
  createPlatform,
  createProject,
  deleteAccount,
  deleteProject,
  logHistory,
  permanentlyDeleteAccount,
  restoreAccount,
  toggleFavorite,
  toggleProjectFavorite,
  unarchiveAccount,
  updateAccount,
  updateProject,
  type SaveAccountInput,
} from "./lib/db";
import type { AccountFormValues, AccountWithRelations, ProjectFormValues, ProjectWithRelations, ViewState } from "./types";

function App() {
  const vaultStatus = useVaultStore((s) => s.status);
  const refreshVault = useVaultStore((s) => s.refresh);
  const lock = useVaultStore((s) => s.lock);
  const settings = useSettingsStore();
  const push = useToastStore((s) => s.push);
  const { t } = useTranslation();

  const unlocked = vaultStatus === "unlocked";
  const library = useLibrary(unlocked);

  const [view, setView] = useState<ViewState>({ type: "dashboard" });
  const [search, setSearch] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountWithRelations | null>(null);
  const [detailAccount, setDetailAccount] = useState<AccountWithRelations | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AccountWithRelations | null>(null);
  const [platformManagerOpen, setPlatformManagerOpen] = useState(false);
  const [quickPlatformFormOpen, setQuickPlatformFormOpen] = useState(false);
  const [lastCreatedPlatformId, setLastCreatedPlatformId] = useState<number | null>(null);
  const [projectFormOpen, setProjectFormOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<ProjectWithRelations | null>(null);
  const [pendingDeleteProject, setPendingDeleteProject] = useState<ProjectWithRelations | null>(null);
  const [quickProjectFormOpen, setQuickProjectFormOpen] = useState(false);
  const [lastCreatedProjectId, setLastCreatedProjectId] = useState<number | null>(null);
  const [projectSearch, setProjectSearch] = useState("");

  useEffect(() => {
    refreshVault();
  }, [refreshVault]);

  useEffect(() => {
    if (unlocked) settings.load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unlocked]);

  useAutoLock(unlocked ? settings.autoLockMinutes : 0, () => {
    lock();
    push(t("unlock.lockedByInactivityToast"), "info");
  });

  // Bloqueio opcional ao minimizar/perder visibilidade (Fase 2 — desligado por padrão).
  useEffect(() => {
    if (!unlocked || !settings.lockOnMinimize) return;
    const handler = () => {
      if (document.visibilityState === "hidden") lock();
    };
    document.addEventListener("visibilitychange", handler);
    return () => document.removeEventListener("visibilitychange", handler);
  }, [unlocked, settings.lockOnMinimize, lock]);

  const filteredAccounts = useMemo(() => {
    let list = library.accounts;
    if (view.type === "platform") list = list.filter((a) => a.platform_id === view.platformId);
    if (view.type === "favorites") list = list.filter((a) => a.favorite);
    if (search) list = list.filter((a) => matchesSearch(a, search));
    return list;
  }, [library.accounts, view, search]);

  const dashboardAccounts = useMemo(() => {
    return search ? library.accounts.filter((a) => matchesSearch(a, search)) : library.accounts;
  }, [library.accounts, search]);

  const filteredProjects = useMemo(() => {
    if (!projectSearch.trim()) return library.projects;
    const q = projectSearch.trim().toLowerCase();
    return library.projects.filter(
      (p) => p.name.toLowerCase().includes(q) || p.tags.some((t) => t.name.toLowerCase().includes(q)),
    );
  }, [library.projects, projectSearch]);

  const currentProject = view.type === "project" ? library.projects.find((p) => p.id === view.projectId) ?? null : null;
  const currentProjectAccounts = useMemo(() => {
    if (!currentProject) return [];
    return library.accounts.filter((a) => a.projects.some((p) => p.id === currentProject.id));
  }, [library.accounts, currentProject]);

  const filteredArchivedAccounts = useMemo(() => {
    return search ? library.archivedAccounts.filter((a) => matchesSearch(a, search)) : library.archivedAccounts;
  }, [library.archivedAccounts, search]);

  // Fase 4 (SECURITY_AUDIT_PHASE_4.md): a WebView não cifra mais nada aqui — envia
  // password/notes/2FA em texto puro, e é o Rust (`create_account`/`update_account`) quem cifra
  // internamente antes de gravar. `preserveFields` continua existindo com a mesma semântica de
  // antes (campo que falhou ao descriptografar e o usuário não editou), só que agora o Rust
  // resolve isso mantendo o ciphertext antigo, sem nunca precisar decifrá-lo.
  async function handleSaveAccount(values: AccountFormValues, preserveFields: SensitiveField[] = []) {
    const passwordChanged = values.password.trim() !== "";

    const payload: SaveAccountInput = {
      name: values.name.trim(),
      platform_id: values.platform_id,
      category: values.category.trim() || null,
      username: values.username.trim() || null,
      email: values.email.trim() || null,
      password: passwordChanged ? values.password : null,
      login_url: values.login_url.trim() || null,
      website_url: values.website_url.trim() || null,
      notes: values.notes,
      favorite: values.favorite,
      avatar_image_id: values.avatar_image_id,
      tagNames: values.tags,
      projectIds: values.projectIds,
      status: values.status,
      two_factor_enabled: values.two_factor_enabled,
      two_factor_method: values.two_factor_enabled ? values.two_factor_method : null,
      two_factor_phone: values.two_factor_phone,
      two_factor_email: values.two_factor_email,
      two_factor_app: values.two_factor_app,
      two_factor_notes: values.two_factor_notes,
      preserveFields,
    };

    if (values.id) {
      await updateAccount(values.id, payload);
      await logAccountChanges(editingAccount, payload, passwordChanged);
      push(t("accounts.toasts.updated"), "success");
    } else {
      await createAccount(payload);
      push(t("accounts.toasts.added"), "success");
    }
    await library.refresh();
  }

  async function logAccountChanges(before: AccountWithRelations | null, after: SaveAccountInput, passwordChanged: boolean) {
    if (!before) return;
    const accountId = before.id;
    if (before.username !== after.username) {
      await logHistory(accountId, "username_changed", `${before.username ?? "—"} → ${after.username ?? "—"}`);
    }
    if (before.email !== after.email) {
      await logHistory(accountId, "email_changed");
    }
    if (passwordChanged) {
      await logHistory(accountId, "password_changed");
    }
    if (before.platform_id !== after.platform_id) {
      await logHistory(accountId, "platform_changed");
    }
    if (before.status !== after.status) {
      await logHistory(accountId, "status_changed", after.status);
    }
    if (before.avatar_image_id !== after.avatar_image_id) {
      await logHistory(accountId, "avatar_changed");
    }
    const beforeTags = before.tags.map((t) => t.name).sort().join(",");
    const afterTags = [...after.tagNames].sort().join(",");
    if (beforeTags !== afterTags) {
      await logHistory(accountId, "tags_changed");
    }
    const beforeProjects = new Set(before.projects.map((p) => p.id));
    const afterProjects = new Set(after.projectIds);
    for (const id of afterProjects) {
      if (!beforeProjects.has(id)) await logHistory(accountId, "project_added");
    }
    for (const id of beforeProjects) {
      if (!afterProjects.has(id)) await logHistory(accountId, "project_removed");
    }
    if (!before.two_factor_enabled && after.two_factor_enabled) {
      await logHistory(accountId, "two_factor_enabled");
    } else if (before.two_factor_enabled && !after.two_factor_enabled) {
      await logHistory(accountId, "two_factor_disabled");
    }
  }

  async function handleDeleteAccount() {
    if (!pendingDelete) return;
    await deleteAccount(pendingDelete.id);
    setPendingDelete(null);
    setDetailAccount(null);
    await library.refresh();
    push(t("accounts.toasts.movedToTrash"), "success");
  }

  async function handleToggleFavorite(account: AccountWithRelations) {
    await toggleFavorite(account.id, !account.favorite);
    await library.refresh();
  }

  async function handleArchiveToggle(account: AccountWithRelations) {
    if (account.status === "archived") {
      await unarchiveAccount(account.id);
      push(t("accounts.toasts.unarchived"), "success");
    } else {
      await archiveAccount(account.id);
      push(t("accounts.toasts.archived"), "success");
    }
    setDetailAccount(null);
    await library.refresh();
  }

  async function handleRestoreFromTrash(account: AccountWithRelations) {
    await restoreAccount(account.id);
    await library.refresh();
    push(t("accounts.toasts.restored"), "success");
  }

  async function handlePermanentlyDelete(account: AccountWithRelations) {
    await permanentlyDeleteAccount(account.id);
    await library.refresh();
    push(t("accounts.toasts.permanentlyDeleted"), "success");
  }

  async function handleCreateQuickPlatform(values: PlatformFormValues) {
    const id = await createPlatform(values);
    await library.refresh();
    setLastCreatedPlatformId(id);
  }

  async function handleSaveProject(values: ProjectFormValues) {
    if (values.id) {
      await updateProject(values.id, values);
      push(t("projects.toasts.updated"), "success");
    } else {
      await createProject(values);
      push(t("projects.toasts.created"), "success");
    }
    await library.refresh();
  }

  async function handleCreateQuickProject(values: ProjectFormValues) {
    const id = await createProject(values);
    await library.refresh();
    setLastCreatedProjectId(id);
  }

  async function handleDeleteProject() {
    if (!pendingDeleteProject) return;
    await deleteProject(pendingDeleteProject.id);
    setPendingDeleteProject(null);
    if (view.type === "project" && view.projectId === pendingDeleteProject.id) {
      setView({ type: "projects" });
    }
    await library.refresh();
    push(t("projects.toasts.deleted"), "success");
  }

  async function handleToggleProjectFavorite(project: ProjectWithRelations) {
    await toggleProjectFavorite(project.id, !project.favorite);
    await library.refresh();
  }

  if (vaultStatus === "loading") {
    return <div className="flex h-screen items-center justify-center bg-[var(--color-bg)]" />;
  }
  if (vaultStatus === "uninitialized") {
    return <CreateMasterPassword />;
  }
  if (vaultStatus === "locked") {
    return <UnlockScreen />;
  }

  const viewTitle =
    view.type === "dashboard"
      ? t("layout.viewTitles.dashboard")
      : view.type === "favorites"
        ? t("layout.viewTitles.favorites")
        : view.type === "settings"
          ? t("layout.viewTitles.settings")
          : view.type === "projects"
            ? t("layout.viewTitles.projects")
            : view.type === "project"
              ? currentProject?.name ?? t("layout.viewTitles.projectFallback")
              : view.type === "archived"
                ? t("layout.viewTitles.archived")
                : view.type === "trash"
                  ? t("layout.viewTitles.trash")
                  : library.platforms.find((p) => p.id === view.platformId)?.name ?? t("layout.viewTitles.platformFallback");

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--color-bg)] text-[var(--color-text)]">
      <Sidebar
        view={view}
        onNavigate={setView}
        platforms={library.platforms}
        countsByPlatform={library.countsByPlatform}
        favoritesCount={library.favoritesCount}
        projectsCount={library.projects.length}
        archivedCount={library.archivedAccounts.length}
        trashCount={library.trashedAccounts.length}
        onLock={() => lock()}
      />

      <div className="flex flex-1 flex-col overflow-hidden">
        {view.type !== "settings" && view.type !== "project" && view.type !== "projects" && view.type !== "trash" && (
          <TopBar
            title={viewTitle}
            search={search}
            onSearchChange={setSearch}
            onAddAccount={() => {
              setEditingAccount(null);
              setFormOpen(true);
            }}
            viewMode={settings.viewMode}
            onViewModeChange={settings.setViewMode}
            listScale={settings.listScale}
            onListScaleChange={settings.setListScale}
          />
        )}

        {view.type === "projects" && (
          <TopBar
            title={viewTitle}
            search={projectSearch}
            onSearchChange={setProjectSearch}
            searchPlaceholder={t("layout.topbar.searchProjectPlaceholder")}
            addLabel={t("layout.topbar.addProject")}
            onAddAccount={() => {
              setEditingProject(null);
              setProjectFormOpen(true);
            }}
            viewMode={settings.viewMode}
            onViewModeChange={settings.setViewMode}
            listScale={settings.listScale}
            onListScaleChange={settings.setListScale}
          />
        )}

        <div className="flex-1 overflow-y-auto">
          {view.type === "settings" && (
            <SettingsView
              platforms={library.platforms}
              countsByPlatform={library.countsByPlatform}
              onPlatformsChanged={library.refresh}
              projects={library.projects}
              tags={library.tags}
            />
          )}

          {view.type === "projects" && (
            <div className="p-6">
              <ProjectsBoard
                projects={filteredProjects}
                viewMode={settings.viewMode}
                onOpen={(project) => setView({ type: "project", projectId: project.id })}
                onToggleFavorite={handleToggleProjectFavorite}
                onAddProject={() => {
                  setEditingProject(null);
                  setProjectFormOpen(true);
                }}
              />
            </div>
          )}

          {view.type === "project" && currentProject && (
            <ProjectDetailView
              project={currentProject}
              accounts={currentProjectAccounts}
              viewMode={settings.viewMode}
              onBack={() => setView({ type: "projects" })}
              onEdit={() => {
                setEditingProject(currentProject);
                setProjectFormOpen(true);
              }}
              onToggleFavorite={() => handleToggleProjectFavorite(currentProject)}
              onDelete={() => setPendingDeleteProject(currentProject)}
              onOpenAccountDetail={setDetailAccount}
              onEditAccount={(a) => {
                setEditingAccount(a);
                setFormOpen(true);
              }}
              onToggleAccountFavorite={handleToggleFavorite}
              onAddAccount={() => {
                setEditingAccount(null);
                setFormOpen(true);
              }}
            />
          )}

          {view.type === "dashboard" && (
            <div className="space-y-6 p-6">
              <div>
                <p className="mb-3 text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">{t("layout.dashboard.categoriesHeading")}</p>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
                  {library.platforms.map((platform) => (
                    <CategoryCard
                      key={platform.id}
                      icon={platform.icon}
                      logoImageId={platform.logo_image_id}
                      name={platform.name}
                      count={library.countsByPlatform[platform.id] ?? 0}
                      onClick={() => setView({ type: "platform", platformId: platform.id })}
                    />
                  ))}
                  <button
                    onClick={() => setPlatformManagerOpen(true)}
                    className="flex items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] px-4 py-3.5 text-sm text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)]"
                  >
                    {t("layout.dashboard.managePlatforms")}
                  </button>
                </div>
              </div>

              <div>
                <p className="mb-3 text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">{t("layout.dashboard.allAccountsHeading")}</p>
                <AccountsBoard
                  accounts={dashboardAccounts}
                  viewMode={settings.viewMode}
                  onOpenDetail={setDetailAccount}
                  onEdit={(a) => {
                    setEditingAccount(a);
                    setFormOpen(true);
                  }}
                  onToggleFavorite={handleToggleFavorite}
                  emptyTitle={t("layout.dashboard.emptyTitle")}
                  emptyDescription={t("layout.dashboard.emptyDescription")}
                  onAddAccount={() => {
                    setEditingAccount(null);
                    setFormOpen(true);
                  }}
                />
              </div>
            </div>
          )}

          {(view.type === "platform" || view.type === "favorites") && (
            <div className="p-6">
              <AccountsBoard
                accounts={filteredAccounts}
                viewMode={settings.viewMode}
                onOpenDetail={setDetailAccount}
                onEdit={(a) => {
                  setEditingAccount(a);
                  setFormOpen(true);
                }}
                onToggleFavorite={handleToggleFavorite}
                emptyTitle={view.type === "favorites" ? t("layout.favoritesEmptyTitle") : t("layout.platformEmptyTitle")}
                emptyDescription={view.type === "favorites" ? t("layout.favoritesEmptyDescription") : t("layout.platformEmptyDescription")}
                onAddAccount={() => {
                  setEditingAccount(null);
                  setFormOpen(true);
                }}
              />
            </div>
          )}

          {view.type === "archived" && (
            <div className="p-6">
              <AccountsBoard
                accounts={filteredArchivedAccounts}
                viewMode={settings.viewMode}
                onOpenDetail={setDetailAccount}
                onEdit={(a) => {
                  setEditingAccount(a);
                  setFormOpen(true);
                }}
                onToggleFavorite={handleToggleFavorite}
                emptyTitle={t("layout.archivedEmptyTitle")}
                emptyDescription={t("layout.archivedEmptyDescription")}
                onAddAccount={() => {
                  setEditingAccount(null);
                  setFormOpen(true);
                }}
              />
            </div>
          )}

          {view.type === "trash" && (
            <TrashView accounts={library.trashedAccounts} onRestore={handleRestoreFromTrash} onPermanentlyDelete={handlePermanentlyDelete} />
          )}
        </div>
      </div>

      <AccountForm
        open={formOpen}
        onClose={() => setFormOpen(false)}
        onSubmit={handleSaveAccount}
        platforms={library.platforms}
        projects={library.projects}
        tags={library.tags}
        editingAccount={editingAccount}
        defaultPlatformId={view.type === "platform" ? view.platformId : null}
        onRequestNewPlatform={() => setQuickPlatformFormOpen(true)}
        newlyCreatedPlatformId={lastCreatedPlatformId}
        onNewPlatformConsumed={() => setLastCreatedPlatformId(null)}
        onRequestNewProject={() => setQuickProjectFormOpen(true)}
        newlyCreatedProjectId={lastCreatedProjectId}
        onNewProjectConsumed={() => setLastCreatedProjectId(null)}
      />

      <AccountDetailModal
        account={detailAccount}
        onClose={() => setDetailAccount(null)}
        onEdit={() => {
          setEditingAccount(detailAccount);
          setDetailAccount(null);
          setFormOpen(true);
        }}
        onDelete={() => setPendingDelete(detailAccount)}
        onArchiveToggle={() => detailAccount && handleArchiveToggle(detailAccount)}
      />

      <ConfirmDialog
        open={!!pendingDelete}
        title={t("accounts.confirmDeleteTitle")}
        message={t("accounts.confirmDeleteMessage", { name: pendingDelete?.name ?? "" })}
        confirmLabel={t("accounts.confirmDeleteLabel")}
        danger
        onConfirm={handleDeleteAccount}
        onCancel={() => setPendingDelete(null)}
      />

      <PlatformManagerModal
        open={platformManagerOpen}
        onClose={() => setPlatformManagerOpen(false)}
        platforms={library.platforms}
        countsByPlatform={library.countsByPlatform}
        onChanged={library.refresh}
      />

      <PlatformForm
        open={quickPlatformFormOpen}
        onClose={() => setQuickPlatformFormOpen(false)}
        onSubmit={handleCreateQuickPlatform}
        editingPlatform={null}
      />

      <ProjectForm
        open={projectFormOpen}
        onClose={() => setProjectFormOpen(false)}
        onSubmit={handleSaveProject}
        editingProject={editingProject}
        tags={library.tags}
      />

      <ProjectForm
        open={quickProjectFormOpen}
        onClose={() => setQuickProjectFormOpen(false)}
        onSubmit={handleCreateQuickProject}
        editingProject={null}
        tags={library.tags}
      />

      <ConfirmDialog
        open={!!pendingDeleteProject}
        title={t("projects.confirmDeleteTitle")}
        message={t("projects.confirmDeleteMessage", { name: pendingDeleteProject?.name ?? "" })}
        confirmLabel={t("projects.confirmDeleteLabel")}
        danger
        onConfirm={handleDeleteProject}
        onCancel={() => setPendingDeleteProject(null)}
      />

      <ToastContainer />
    </div>
  );
}

export default App;
