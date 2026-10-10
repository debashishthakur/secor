create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text,
  api_key text,
  constraint display_name_length check (char_length(display_name) >= 3)
);
