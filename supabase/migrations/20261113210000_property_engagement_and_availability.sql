-- DESTATE property engagement, price history, and availability confirmation
-- Public listings remain browseable; private engagement data is owner-scoped.

alter table public.properties
  add column if not exists availability_confirmed_at timestamptz not null default now(),
  add column if not exists expires_at timestamptz not null default (now() + interval '30 days');

update public.properties
set availability_confirmed_at = coalesce(availability_confirmed_at, created_at, now()),
    expires_at = coalesce(expires_at, now() + interval '30 days');

create table if not exists public.property_favorites (
  user_id uuid not null references auth.users(id) on delete cascade,
  property_id uuid not null references public.properties(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, property_id)
);

alter table public.property_favorites enable row level security;
revoke all on public.property_favorites from anon, authenticated;
grant select, insert, delete on public.property_favorites to authenticated;

drop policy if exists "Users read own property favorites" on public.property_favorites;
create policy "Users read own property favorites"
  on public.property_favorites for select to authenticated
  using ((select auth.uid()) = user_id);

drop policy if exists "Users add own published property favorites" on public.property_favorites;
create policy "Users add own published property favorites"
  on public.property_favorites for insert to authenticated
  with check (
    (select auth.uid()) = user_id
    and exists (
      select 1 from public.properties p
      where p.id = property_id
        and p.status = 'published'
        and p.expires_at > now()
    )
  );

drop policy if exists "Users remove own property favorites" on public.property_favorites;
create policy "Users remove own property favorites"
  on public.property_favorites for delete to authenticated
  using ((select auth.uid()) = user_id);

create schema if not exists private;

create table if not exists private.property_view_events (
  id bigint generated always as identity primary key,
  property_id uuid not null references public.properties(id) on delete cascade,
  visitor_id uuid not null,
  viewed_on date not null default current_date,
  created_at timestamptz not null default now(),
  unique (property_id, visitor_id, viewed_on)
);
alter table private.property_view_events enable row level security;
revoke all on private.property_view_events from public, anon, authenticated;

create table if not exists private.property_price_history (
  id bigint generated always as identity primary key,
  property_id uuid not null references public.properties(id) on delete cascade,
  old_price numeric not null,
  new_price numeric not null,
  changed_at timestamptz not null default now()
);
alter table private.property_price_history enable row level security;
revoke all on private.property_price_history from public, anon, authenticated;
create index if not exists property_view_events_property_date_idx
  on private.property_view_events(property_id, viewed_on);
create index if not exists property_price_history_property_changed_idx
  on private.property_price_history(property_id, changed_at desc);
create index if not exists property_favorites_property_idx
  on public.property_favorites(property_id);

create or replace function private.log_property_price_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.price is distinct from old.price then
    insert into private.property_price_history(property_id, old_price, new_price)
    values (new.id, old.price, new.price);
  end if;
  return new;
end;
$$;
revoke all on function private.log_property_price_change() from public, anon, authenticated;

drop trigger if exists property_price_history_after_update on public.properties;
create trigger property_price_history_after_update
after update of price on public.properties
for each row execute function private.log_property_price_change();

create or replace function public.record_property_view(
  p_property_id uuid,
  p_visitor_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_property_id is null or p_visitor_id is null then
    return false;
  end if;

  if not exists (
    select 1 from public.properties p
    where p.id = p_property_id
      and p.status = 'published'
      and p.expires_at > now()
  ) then
    return false;
  end if;

  insert into private.property_view_events(property_id, visitor_id, viewed_on)
  values (p_property_id, p_visitor_id, current_date)
  on conflict (property_id, visitor_id, viewed_on) do nothing;

  return true;
end;
$$;
revoke all on function public.record_property_view(uuid, uuid) from public;
grant execute on function public.record_property_view(uuid, uuid) to anon, authenticated;

create or replace function public.get_property_price_history(p_property_id uuid)
returns table(old_price numeric, new_price numeric, changed_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if not exists (
    select 1 from public.properties p
    where p.id = p_property_id
      and (
        (p.status = 'published' and p.expires_at > now())
        or (v_uid is not null and p.owner_id = v_uid)
      )
  ) then
    return;
  end if;

  return query
  select h.old_price, h.new_price, h.changed_at
  from private.property_price_history h
  where h.property_id = p_property_id
  order by h.changed_at desc
  limit 20;
end;
$$;
revoke all on function public.get_property_price_history(uuid) from public;
grant execute on function public.get_property_price_history(uuid) to anon, authenticated;

create or replace function public.get_my_property_stats()
returns table(
  property_id uuid,
  title text,
  price numeric,
  status text,
  expires_at timestamptz,
  view_count bigint,
  contact_count bigint,
  favorite_count bigint
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  return query
  select
    p.id,
    p.title,
    p.price,
    p.status,
    p.expires_at,
    (select count(*) from private.property_view_events v where v.property_id = p.id),
    (select count(*) from public.property_contact_events c where c.property_id = p.id),
    (select count(*) from public.property_favorites f where f.property_id = p.id)
  from public.properties p
  where p.owner_id = v_uid
  order by p.created_at desc;
end;
$$;
revoke all on function public.get_my_property_stats() from public;
grant execute on function public.get_my_property_stats() to authenticated;

create or replace function public.confirm_property_availability(p_property_id uuid)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_expires_at timestamptz;
begin
  if auth.uid() is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  update public.properties
  set availability_status = 'available',
      availability_confirmed_at = now(),
      expires_at = now() + interval '30 days'
  where id = p_property_id
    and owner_id = auth.uid()
    and status = 'published'
  returning expires_at into v_expires_at;

  if v_expires_at is null then
    raise exception 'PROPERTY_NOT_FOUND_OR_NOT_OWNED';
  end if;

  return v_expires_at;
end;
$$;
revoke all on function public.confirm_property_availability(uuid) from public;
grant execute on function public.confirm_property_availability(uuid) to authenticated;
