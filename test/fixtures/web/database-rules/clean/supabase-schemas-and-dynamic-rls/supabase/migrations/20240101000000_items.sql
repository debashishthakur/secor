create table public.items (id bigint primary key, owner uuid);
alter table public.items enable row level security;
create table public.events (id bigint primary key);
