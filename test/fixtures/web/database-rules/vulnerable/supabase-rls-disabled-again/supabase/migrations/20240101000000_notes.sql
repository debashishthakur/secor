create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "owner reads" on public.notes for select to authenticated using (auth.uid() = owner);
