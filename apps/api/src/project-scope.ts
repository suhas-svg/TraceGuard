import type { Pool, PoolClient } from "pg";
import type { Principal } from "./auth.js";

// Project scope is the policy/data boundary inside a workspace (§7.1/§13.1).
// Workspace predicates stay in place for compatibility, but every new identity
// decision also carries a project. These helpers centralize the fallback rules
// so an old caller that does not name a project lands in the workspace default
// instead of writing an unscoped row.

export type Db = Pool | PoolClient;

export interface ProjectRow {
  id: string;
  workspace_id: string;
  name: string;
  status: string;
  created_at: string;
}

export async function ensureDefaultProject(db: Db, workspaceId: string): Promise<string> {
  const res = await db.query("SELECT ensure_default_project($1) AS id", [workspaceId]);
  return res.rows[0].id as string;
}

export async function defaultProjectId(db: Db, workspaceId: string): Promise<string | null> {
  const found = await db.query(
    "SELECT id FROM projects WHERE workspace_id = $1 AND name = 'default'",
    [workspaceId]
  );
  return (found.rows[0]?.id as string | undefined) ?? null;
}

export async function projectById(db: Db, projectId: string): Promise<ProjectRow | null> {
  const res = await db.query(
    "SELECT id, workspace_id, name, status, created_at FROM projects WHERE id = $1",
    [projectId]
  );
  return (res.rows[0] as ProjectRow | undefined) ?? null;
}

export function projectAllowed(principal: Principal | undefined, projectId: string): boolean {
  if (!principal) return false;
  if (principal.projects === "all") return true;
  return principal.projects.includes(projectId);
}

// Adds a project predicate for list queries. "all" adds nothing; an empty
// scope matches nothing, which is the safe answer for a principal with no
// projects.
export function projectClause(
  principal: Principal | undefined,
  params: unknown[],
  column: string
): string | null {
  if (!principal || principal.projects === "all") return null;
  params.push(principal.projects);
  return `${column} = ANY($${params.length}::uuid[])`;
}

export async function projectIdsForWorkspaces(
  db: Db,
  workspaces: "all" | string[]
): Promise<"all" | string[]> {
  if (workspaces === "all") return "all";
  if (workspaces.length === 0) return [];
  const res = await db.query(
    "SELECT id FROM projects WHERE workspace_id = ANY($1::uuid[]) ORDER BY created_at, id",
    [workspaces]
  );
  return res.rows.map((r) => r.id as string);
}

export interface ResolveProjectInput {
  workspaceId?: string | null;
  projectId?: string | null;
  projectName?: string | null;
}

export interface ResolvedProject {
  project: ProjectRow;
  workspaceId: string;
}

// Resolution order:
// 1. an explicit project id/name, which must be allowed for the principal;
// 2. a principal pinned to exactly one project;
// 3. the workspace default project.
// Multiple allowed projects inside a workspace are ambiguous without an
// explicit id, so callers that need a single target must name one.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function resolveProject(
  db: Db,
  principal: Principal | undefined,
  input: ResolveProjectInput = {}
): Promise<ResolvedProject | null> {
  // OAuth test fixtures and older tokens may carry non-UUID workspace ids.
  // Never hand those to a uuid cast.
  if (input.workspaceId && !UUID_RE.test(input.workspaceId)) return null;
  if (input.projectId && !UUID_RE.test(input.projectId)) return null;

  const requested = input.projectId ?? null;
  if (requested) {
    const project = await projectById(db, requested);
    if (!project) return null;
    if (input.workspaceId && project.workspace_id !== input.workspaceId) return null;
    if (!projectAllowed(principal, project.id)) return null;
    return { project, workspaceId: project.workspace_id };
  }

  const name = input.projectName ?? null;
  if (name) {
    if (!input.workspaceId) return null;
    const found = await db.query(
      "SELECT id, workspace_id, name, status, created_at FROM projects WHERE workspace_id = $1 AND name = $2",
      [input.workspaceId, name]
    );
    const project = found.rows[0] as ProjectRow | undefined;
    if (!project || !projectAllowed(principal, project.id)) return null;
    return { project, workspaceId: project.workspace_id };
  }

  let workspaceId = input.workspaceId ?? null;
  if (!workspaceId) {
    if (principal?.projects === "all") {
      const found = await db.query("SELECT id FROM workspaces WHERE name = 'default'");
      workspaceId = (found.rows[0]?.id as string | undefined) ?? null;
    } else if (Array.isArray(principal?.projects) && principal.projects.length === 1) {
      const project = await projectById(db, principal.projects[0]);
      if (!project) return null;
      if (input.workspaceId && project.workspace_id !== input.workspaceId) return null;
      return { project, workspaceId: project.workspace_id };
    }
  }
  if (!workspaceId) {
    const found = await db.query("SELECT id FROM workspaces WHERE name = 'default'");
    workspaceId = (found.rows[0]?.id as string | undefined) ?? null;
  }
  if (!workspaceId) return null;

  if (Array.isArray(principal?.projects)) {
    if (principal.projects.length === 0) return null;
    const allowed = await db.query(
      `SELECT id, workspace_id, name, status, created_at
         FROM projects
        WHERE workspace_id = $1 AND id = ANY($2::uuid[])
        ORDER BY created_at, id`,
      [workspaceId, principal.projects]
    );
    if (allowed.rows.length === 1) {
      return { project: allowed.rows[0] as ProjectRow, workspaceId };
    }
    // More than one allowed project and no explicit choice: fall through to
    // the workspace default only if that default is itself allowed.
  }

  const id = await ensureDefaultProject(db, workspaceId);
  const project = await projectById(db, id);
  if (!project) return null;
  if (!projectAllowed(principal, project.id)) return null;
  return { project, workspaceId };
}
