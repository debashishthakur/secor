create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  body text
);

alter table public.notes enable row level security;

create policy "Owners manage their notes" on public.notes
  for all using ((select auth.uid()) = user_id);
