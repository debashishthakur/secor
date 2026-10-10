-- Initial schema
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users not null,
  task text check (char_length(task) > 3)
);

create table profiles (
  id uuid primary key references auth.users,
  username text
);
alter table profiles enable row level security;
