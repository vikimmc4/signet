-- Signet backend schema
-- Paste this whole file into Supabase → SQL Editor → Run. It is safe to
-- re-run: every object is created with "if not exists" or "or replace".
--
-- Design notes
--   * The tables are fully locked down (RLS on, no policies). Nothing reads or
--     writes them directly. All access goes through the sg_* functions below,
--     which run as the owner and are keyed by an unguessable envelope id.
--     So the public anon key in the page cannot be used to enumerate anything.
--   * Timestamps come from now() on the database, never from the signer's
--     device clock, and IP addresses are read from the request headers by the
--     database itself. Both are therefore outside the signer's control, which
--     is the whole point of an audit trail.
--   * Creating an envelope requires a passphrase you choose below. Without it
--     a stranger who found the site could fill your database.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- tables ---

create table if not exists envelopes (
  id            text primary key,
  created_at    timestamptz not null default now(),
  created_ip    text,
  title         text        not null,
  message       text        not null default '',
  sender_name   text        not null,
  sender_email  text        not null,
  pdf_b64       text        not null,   -- the original document
  pdf_sha256    text        not null,   -- fingerprint of the original
  page_count    int         not null,
  doc           jsonb       not null,   -- {signers:[...], fields:[...]}
  status        text        not null default 'sent',   -- sent | signed
  signed_b64    text,                   -- the finished document
  signed_sha256 text,
  completed_at  timestamptz
);

create table if not exists events (
  id          bigserial primary key,
  envelope_id text        not null references envelopes(id) on delete cascade,
  at          timestamptz not null default now(),
  ip          text,
  kind        text        not null,     -- created | opened | signed
  actor       text,
  user_agent  text,
  detail      jsonb       not null default '{}'::jsonb
);

create index if not exists events_envelope_idx on events(envelope_id, at);

-- Holds the hashed sender passphrase. One row, id = 1.
create table if not exists config (
  id       int primary key default 1,
  key_hash text not null,
  check (id = 1)
);

alter table envelopes enable row level security;
alter table events    enable row level security;
alter table config    enable row level security;
-- Deliberately no policies: direct table access is denied to everyone.

-- ------------------------------------------------------------- internals ---

-- The caller's IP, as seen by the API gateway. Only meaningful inside the
-- security-definer functions below, which is the only place it is used.
create or replace function client_ip() returns text
language sql stable as $$
  select nullif(
    split_part(
      coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''),
      ',', 1),
    '')
$$;

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

-- ------------------------------------------------------------------ API ----

-- Create an envelope and return its unguessable id.
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

-- Fetch an envelope for signing, and record that it was opened.
create or replace function sg_open(p_id text, p_user_agent text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare e envelopes;
begin
  select * into e from envelopes where id = p_id;
  if not found then return null; end if;

  insert into events (envelope_id, ip, kind, user_agent)
  values (p_id, client_ip(), 'opened', p_user_agent);

  return jsonb_build_object(
    'id',         e.id,
    'title',      e.title,
    'message',    e.message,
    'sender',     jsonb_build_object('name', e.sender_name, 'email', e.sender_email),
    'pdf',        e.pdf_b64,
    'pdfSha256',  e.pdf_sha256,
    'pageCount',  e.page_count,
    'doc',        e.doc,
    'status',     e.status,
    'createdAt',  e.created_at
  );
end $$;

-- Record one signer's field values. The merge happens here, on the server, so
-- a signer cannot overwrite anybody else's signature.
create or replace function sg_sign(
  p_id         text,
  p_signer_id  text,
  p_values     jsonb,     -- {fieldId: value, ...}
  p_consent    text,
  p_user_agent text
) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  e       envelopes;
  v_doc   jsonb;
  v_all   boolean;
  v_ip    text := client_ip();
  v_now   timestamptz := now();
begin
  select * into e from envelopes where id = p_id for update;
  if not found then raise exception 'That signing link is not valid'; end if;
  if e.status = 'signed' then raise exception 'This document is already complete'; end if;

  if not exists (select 1 from jsonb_array_elements(e.doc -> 'signers') s
                 where s ->> 'id' = p_signer_id) then
    raise exception 'Unknown signer';
  end if;

  v_doc := e.doc;

  v_doc := jsonb_set(v_doc, '{fields}', coalesce((
    select jsonb_agg(
      case when f ->> 'signer' = p_signer_id and p_values ? (f ->> 'id')
           then f || jsonb_build_object('value', p_values -> (f ->> 'id'))
           else f end
      order by ord)
    from jsonb_array_elements(v_doc -> 'fields') with ordinality t(f, ord)
  ), '[]'::jsonb));

  v_doc := jsonb_set(v_doc, '{signers}', coalesce((
    select jsonb_agg(
      case when s ->> 'id' = p_signer_id
           then s || jsonb_build_object('signedAt', v_now, 'ip', v_ip,
                                        'agent', p_user_agent, 'consent', p_consent)
           else s end
      order by ord)
    from jsonb_array_elements(v_doc -> 'signers') with ordinality t(s, ord)
  ), '[]'::jsonb));

  -- Complete once every signer who actually has fields has signed.
  select coalesce(bool_and(s ->> 'signedAt' is not null), true) into v_all
  from jsonb_array_elements(v_doc -> 'signers') s
  where exists (select 1 from jsonb_array_elements(v_doc -> 'fields') f
                where f ->> 'signer' = s ->> 'id');

  update envelopes
     set doc          = v_doc,
         status       = case when v_all then 'signed' else status end,
         completed_at = case when v_all then v_now else completed_at end
   where id = p_id;

  insert into events (envelope_id, ip, kind, actor, user_agent, detail)
  values (p_id, v_ip, 'signed', p_signer_id, p_user_agent,
          jsonb_build_object('consent', p_consent,
                             'fields', (select jsonb_agg(k) from jsonb_object_keys(p_values) k)));

  return jsonb_build_object('status', case when v_all then 'signed' else 'partial' end,
                            'doc', v_doc, 'signedAt', v_now, 'ip', v_ip);
end $$;

-- Attach the finished PDF that the signer's browser produced.
create or replace function sg_store_signed(p_id text, p_pdf_b64 text, p_sha256 text)
returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  update envelopes
     set signed_b64 = p_pdf_b64, signed_sha256 = p_sha256
   where id = p_id;
end $$;

-- Status of the envelopes whose ids the caller already holds.
create or replace function sg_status(p_ids text[])
returns jsonb
language sql security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'id',          id,
           'title',       title,
           'status',      status,
           'createdAt',   created_at,
           'completedAt', completed_at,
           'hasSigned',   signed_b64 is not null,
           'signers',     (select jsonb_agg(jsonb_build_object(
                             'name', s ->> 'name', 'email', s ->> 'email',
                             'signedAt', s ->> 'signedAt'))
                           from jsonb_array_elements(doc -> 'signers') s)
         ) order by created_at desc), '[]'::jsonb)
  from envelopes where id = any(p_ids)
$$;

create or replace function sg_signed(p_id text)
returns jsonb
language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object('pdf', signed_b64, 'sha256', signed_sha256, 'title', title)
  from envelopes where id = p_id
$$;

-- The audit record used to build the certificate page.
create or replace function sg_events(p_id text)
returns jsonb
language sql security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'at', at, 'ip', ip, 'kind', kind, 'actor', actor, 'ua', user_agent
         ) order by at), '[]'::jsonb)
  from events where envelope_id = p_id
$$;

-- --------------------------------------------------------------- grants ----

revoke execute on function client_ip()          from anon, authenticated;
revoke execute on function check_key(text)      from anon, authenticated;

grant execute on function sg_create(text,text,text,text,text,text,text,int,jsonb,text) to anon;
grant execute on function sg_open(text,text)                                           to anon;
grant execute on function sg_sign(text,text,jsonb,text,text)                           to anon;
grant execute on function sg_store_signed(text,text,text)                              to anon;
grant execute on function sg_status(text[])                                            to anon;
grant execute on function sg_signed(text)                                              to anon;
grant execute on function sg_events(text)                                              to anon;

-- ------------------------------------------------------- your passphrase ---
-- CHANGE THE PASSPHRASE BELOW before running this file. You type it once in
-- Signet on each device you send from; signers never need it.

insert into config (id, key_hash)
values (1, encode(digest('change-this-passphrase', 'sha256'), 'hex'))
on conflict (id) do update set key_hash = excluded.key_hash;
