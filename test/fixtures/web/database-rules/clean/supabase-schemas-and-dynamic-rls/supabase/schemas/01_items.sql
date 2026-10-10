create table public.items (id bigint primary key, owner uuid);
alter table public.items enable row level security;
