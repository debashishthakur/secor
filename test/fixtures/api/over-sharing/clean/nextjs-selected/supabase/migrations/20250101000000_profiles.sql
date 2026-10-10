create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text,
  api_key text
);
