-- Remove the throwaway envelopes left behind by setup and testing.
-- Run in Supabase → SQL Editor. Look first:
--
--     select id, title, status, created_at from envelopes order by created_at;
--
-- Then delete the test ones. Audit events are removed with them (cascade).

delete from envelopes
where title in (
  'probe',
  'Security probe',
  'Live Round Trip',
  'Rental Agreement',
  'Tenancy Agreement',
  'Committee Resolution',
  'Self Test',
  'Fresh',
  'Offline Test'
);

-- Confirm what is left:
select id, title, status, created_at from envelopes order by created_at;
