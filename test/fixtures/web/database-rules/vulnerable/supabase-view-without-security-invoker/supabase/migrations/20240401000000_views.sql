create table public.accounts (
  id uuid primary key,
  email text not null,
  stripe_customer text
);
alter table public.accounts enable row level security;
create policy "own account" on public.accounts for select to authenticated using (auth.uid() = id);

create view public.account_emails as
  select a.id, a.email from public.accounts a;

create view public.account_ids with (security_invoker = true) as select id from public.accounts;

create view public.account_rollup as select count(*) from account_emails;
