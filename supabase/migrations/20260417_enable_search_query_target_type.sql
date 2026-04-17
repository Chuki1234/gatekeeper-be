-- Allow persisting VT intelligence lookups in scans history.
ALTER TABLE public.scans DROP CONSTRAINT IF EXISTS scans_target_type_check;

ALTER TABLE public.scans
  ADD CONSTRAINT scans_target_type_check
  CHECK (target_type IN ('file', 'url', 'search_query'));
