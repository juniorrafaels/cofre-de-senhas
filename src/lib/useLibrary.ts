import { useCallback, useEffect, useState } from "react";
import { listAccountsWithRelations, listPlatforms, listProjectsWithRelations, listTags } from "./db";
import type { AccountWithRelations, Platform, ProjectWithRelations, Tag } from "../types";

export function useLibrary(enabled: boolean) {
  const [platforms, setPlatforms] = useState<Platform[]>([]);
  const [accounts, setAccounts] = useState<AccountWithRelations[]>([]);
  const [trashedAccounts, setTrashedAccounts] = useState<AccountWithRelations[]>([]);
  const [projects, setProjects] = useState<ProjectWithRelations[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const [p, a, trash, pr, t] = await Promise.all([
      listPlatforms(),
      listAccountsWithRelations("active"),
      listAccountsWithRelations("trash"),
      listProjectsWithRelations(),
      listTags(),
    ]);
    setPlatforms(p);
    setAccounts(a);
    setTrashedAccounts(trash);
    setProjects(pr);
    setTags(t);
    setLoading(false);
  }, []);

  useEffect(() => {
    if (enabled) refresh();
  }, [enabled, refresh]);

  const activeAccounts = accounts.filter((a) => a.status !== "archived");
  const archivedAccounts = accounts.filter((a) => a.status === "archived");

  const countsByPlatform: Record<number, number> = {};
  for (const account of activeAccounts) {
    if (account.platform_id) {
      countsByPlatform[account.platform_id] = (countsByPlatform[account.platform_id] ?? 0) + 1;
    }
  }
  const favoritesCount = activeAccounts.filter((a) => a.favorite).length;

  return {
    platforms,
    accounts: activeAccounts,
    archivedAccounts,
    trashedAccounts,
    projects,
    tags,
    loading,
    refresh,
    countsByPlatform,
    favoritesCount,
  };
}
