/* Users table. create table public.commented (id int); */
create table public."Users" (
  id uuid primary key,
  "Name" text
);
-- create table public.commented_too (id int);
alter table "public"."users" enable row level security;

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer as $fn$
begin
  create table public.ghost (id int);
  insert into public."Users" (id) values (new.id);
  return new;
end;
$fn$;

create table if not exists public.items (note text default 'a;b', other text default E'it\'s; fine');
alter table only public.items enable row level security;
create table public.tmp (id int);
drop table if exists public.tmp cascade;
