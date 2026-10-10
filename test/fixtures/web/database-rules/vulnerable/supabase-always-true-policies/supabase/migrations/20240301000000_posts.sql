create table public.posts (
  id bigint primary key,
  author_id uuid not null,
  body text
);
alter table public.posts enable row level security;

create policy "Anyone can read posts"
  on public.posts for select
  using ( true );

create policy "Anyone can insert posts" on public.posts
  for insert to anon
  with check ((true));

create policy "Authors update" on public.posts for update to authenticated using (auth.uid() = author_id);
create policy "Signed-in read" on public.posts for select to authenticated using (true);
create policy "Narrowing" on public.posts as restrictive for delete using (true);
create policy "Everything" on public.posts to public using (true) with check (auth.uid() = author_id);
