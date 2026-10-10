alter table public.todos enable row level security;
create policy "own todos" on public.todos for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "signed-in read" on public.todos for select to authenticated using (true);

create schema if not exists private;
create table private.audit_log (id bigint primary key, event text);

create table public.scratch (id int);
drop table public.scratch;

create view public.my_todos with (security_invoker = on) as select * from public.todos;
create view public.todo_count as select 1 as one;
