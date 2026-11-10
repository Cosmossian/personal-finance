-- The Vault: share with a partner (Dual income tab). Run once in Supabase after vault-setup.sql:
-- SQL Editor > New query > paste > Run. Touches only vault_* tables.
--
-- How it works: one person makes a code (vault_invites), the other types it in (vault_redeem),
-- which links the two accounts (vault_links). Linked partners can READ each other's vault_ledgers row.
-- Each person can still only change their own.

create table if not exists public.vault_invites (
  code text primary key,
  owner uuid not null default auth.uid() references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '24 hours',
  used_by uuid
);

create table if not exists public.vault_links (
  owner uuid not null references auth.users (id) on delete cascade,
  partner uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (owner, partner)
);

alter table public.vault_invites enable row level security;
alter table public.vault_links enable row level security;

drop policy if exists "vault invites: own" on public.vault_invites;
create policy "vault invites: own" on public.vault_invites
  for all to authenticated
  using (owner = auth.uid())
  with check (owner = auth.uid());

drop policy if exists "vault links: either person reads" on public.vault_links;
create policy "vault links: either person reads" on public.vault_links
  for select to authenticated
  using (auth.uid() = owner or auth.uid() = partner);

drop policy if exists "vault links: either person unlinks" on public.vault_links;
create policy "vault links: either person unlinks" on public.vault_links
  for delete to authenticated
  using (auth.uid() = owner or auth.uid() = partner);

-- linked partners can read (not change) each other's ledger
drop policy if exists "vault: linked partner reads" on public.vault_ledgers;
create policy "vault: linked partner reads" on public.vault_ledgers
  for select to authenticated
  using (exists (
    select 1 from public.vault_links l
    where (l.owner = auth.uid() and l.partner = vault_ledgers.user_id)
       or (l.partner = auth.uid() and l.owner = vault_ledgers.user_id)
  ));

-- typing in a code: checks it and makes the link (runs with extra rights, only does this one thing)
create or replace function public.vault_redeem(p_code text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  o uuid;
  c text := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select owner into o from public.vault_invites
    where code = c and used_by is null and expires_at > now();
  if o is null then raise exception 'That code doesn''t work. It may be mistyped, used already, or older than 24 hours.'; end if;
  if o = auth.uid() then raise exception 'That''s your own code. The other person types it into their Vault.'; end if;
  if exists (select 1 from public.vault_links where auth.uid() in (owner, partner) or o in (owner, partner)) then
    raise exception 'One of you is already linked to someone. Unlink first (Dual income tab).';
  end if;
  insert into public.vault_links (owner, partner) values (o, auth.uid());
  update public.vault_invites set used_by = auth.uid() where code = c;
  return o;
end;
$$;

revoke all on function public.vault_redeem(text) from public;
grant execute on function public.vault_redeem(text) to authenticated;
grant select, insert, delete on public.vault_invites to authenticated;
grant select, delete on public.vault_links to authenticated;
