-- FR-009 asks for budget limits on "an agent or project over a reporting
-- period". Project is the spec's own name for a workspace (§9.1: "the isolated
-- local installation or project namespace"), so a project budget carries a
-- workspace id in ref_id rather than getting a table the spec never defines.
--
-- Widening the check constraint is enough: the scope column already exists, and
-- the workspace_id on the row already says who owns the budget.
ALTER TABLE budgets DROP CONSTRAINT IF EXISTS budgets_scope_check;
ALTER TABLE budgets ADD CONSTRAINT budgets_scope_check
  CHECK (scope IN ('run', 'agent', 'project'));

-- Project budgets are read by target workspace, so index what the check and the
-- list actually filter on.
CREATE INDEX IF NOT EXISTS idx_budgets_project ON budgets(ref_id) WHERE scope = 'project';
