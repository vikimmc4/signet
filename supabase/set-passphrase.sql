-- Set your real sender passphrase.
--
-- Run this in Supabase → SQL Editor. Type your passphrase directly here, in
-- the browser — do not put it in a file in this repo, which is public.
--
-- The passphrase gates creating envelopes. Signers never need it; you type it
-- once per device you send from.

insert into config (id, key_hash)
values (1, encode(extensions.digest('TYPE-YOUR-PASSPHRASE-HERE', 'sha256'), 'hex'))
on conflict (id) do update set key_hash = excluded.key_hash;

-- Optional: clear out the test envelopes created while setting this up.
-- Check what you have first:
--     select id, title, created_at, status from envelopes order by created_at;
-- Then remove the throwaways by title:
--     delete from envelopes where title in ('Security probe', 'probe');
