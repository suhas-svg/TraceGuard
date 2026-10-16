-- Cached input tokens per span, billed at the cached rate instead of the
-- full input rate. NULL means "not reported"; zero means the provider
-- reported no cache hits. Estimates treat NULL as 0 cached tokens.
ALTER TABLE spans ADD COLUMN IF NOT EXISTS cached_tokens INTEGER
  CHECK (cached_tokens IS NULL OR cached_tokens >= 0);
