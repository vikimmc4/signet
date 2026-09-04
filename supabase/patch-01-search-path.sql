-- Signet patch 01 — make pgcrypto reachable from the security-definer functions.
--
-- Supabase installs pgcrypto into the "extensions" schema, not "public". The
-- original functions pinned search_path to "public" alone, so digest() and
-- gen_random_bytes() resolved fine in the SQL editor (whose search path
-- includes extensions) but were invisible at runtime, and sg_create failed
-- with: function digest(text, unknown) does not exist.
--
-- This only changes the search_path of the two affected functions. It does not
-- touch your data or your stored passphrase. Paste it into
-- Supabase → SQL Editor → Run.

create or replace function check_key(p_key text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_hash text;
begin
  select key_hash into v_hash from config where id = 1;
  if v_hash is null then
    raise exception 'Signet is not set up: no sender passphrase has been stored';
  end if;
  if v_hash <> encode(digest(coalesce(p_key, ''), 'sha256'), 'hex') then
    raise exception 'Wrong sender passphrase';
  end if;
end $$;

create or replace function sg_create(
  p_key          text,
  p_title        text,
  p_message      text,
  p_sender_name  text,
  p_sender_email text,
  p_pdf_b64      text,
  p_pdf_sha256   text,
  p_page_count   int,
  p_doc          jsonb,
  p_user_agent   text
) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare v_id text;
begin
  perform check_key(p_key);
  v_id := encode(gen_random_bytes(16), 'hex');

  insert into envelopes (id, created_ip, title, message, sender_name, sender_email,
                         pdf_b64, pdf_sha256, page_count, doc)
  values (v_id, client_ip(), p_title, coalesce(p_message, ''), p_sender_name,
          p_sender_email, p_pdf_b64, p_pdf_sha256, p_page_count, p_doc);

  insert into events (envelope_id, ip, kind, actor, user_agent)
  values (v_id, client_ip(), 'created', p_sender_email, p_user_agent);

  return v_id;
end $$;

revoke execute on function check_key(text) from anon, authenticated;
grant execute on function sg_create(text,text,text,text,text,text,text,int,jsonb,text) to anon;
