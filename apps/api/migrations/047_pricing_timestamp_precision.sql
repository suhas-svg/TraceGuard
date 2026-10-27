-- 047: price timestamps use the same precision as client span timestamps.
--
-- Span timestamps arrive as ISO-8601 with millisecond precision, while
-- `now()` keeps microseconds. A price created in the same millisecond as a
-- span could therefore sort microseconds *after* the span and be excluded by
-- `effective_from <= started_at`, making a just-created price look absent.
-- Truncate the default at the boundary where both values are compared.
ALTER TABLE pricing
  ALTER COLUMN effective_from SET DEFAULT date_trunc('milliseconds', now());
