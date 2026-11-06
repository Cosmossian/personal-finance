-- The Vault (thatonedrawer.com/personal-finance/): one row per account, private to that account.
-- Run once in Supabase: SQL Editor > New query > paste > Run.
-- Same Supabase project as the Recipe Box, the Study and the Library. Touches no other tables.

create table if not exists public.vault_ledgers (
  user_id uuid primary key default auth.uid() references auth.users (id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.vault_ledgers enable row level security;

drop policy if exists "vault: own ledger" on public.vault_ledgers;
create policy "vault: own ledger" on public.vault_ledgers
  for all to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

grant select, insert, update, delete on public.vault_ledgers to authenticated;
