-- DESTATE: users can follow advertiser accounts, independently of individual listings.
create table if not exists public.advertiser_follows (
  follower_id uuid not null references auth.users(id) on delete cascade,
  advertiser_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, advertiser_id),
  constraint advertiser_follows_not_self check (follower_id <> advertiser_id)
);

create index if not exists advertiser_follows_advertiser_idx
  on public.advertiser_follows(advertiser_id, created_at desc);

alter table public.advertiser_follows enable row level security;
revoke all on public.advertiser_follows from anon, authenticated;
grant select on public.advertiser_follows to authenticated;

drop policy if exists "Users read their own advertiser follows" on public.advertiser_follows;
create policy "Users read their own advertiser follows"
  on public.advertiser_follows for select to authenticated
  using ((select auth.uid()) = follower_id);

create or replace function public.follow_advertiser_from_property(p_property_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_advertiser uuid;
begin
  if v_user is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  select p.owner_id into v_advertiser
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_advertiser is null then
    raise exception 'LISTING_UNAVAILABLE';
  end if;
  if v_advertiser = v_user then
    raise exception 'CANNOT_FOLLOW_SELF';
  end if;

  insert into public.advertiser_follows(follower_id, advertiser_id)
  values (v_user, v_advertiser)
  on conflict (follower_id, advertiser_id) do nothing;

  return true;
end;
$$;

create or replace function public.unfollow_advertiser(p_advertiser_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
begin
  if v_user is null then
    raise exception 'AUTH_REQUIRED';
  end if;
  delete from public.advertiser_follows
  where follower_id = v_user and advertiser_id = p_advertiser_id;
  return found;
end;
$$;

create or replace function public.get_followed_advertisers()
returns table (
  advertiser_id uuid,
  advertiser_type text,
  listing_count bigint,
  latest_listing_title text,
  governorate text,
  city text,
  followed_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
begin
  if v_user is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  return query
  select
    f.advertiser_id,
    coalesce(latest.advertiser_type, 'owner')::text,
    coalesce(stats.listing_count, 0)::bigint,
    latest.title::text,
    latest.governorate::text,
    latest.city::text,
    f.created_at
  from public.advertiser_follows f
  left join lateral (
    select count(*)::bigint as listing_count
    from public.properties p
    where p.owner_id = f.advertiser_id
      and p.status = 'published'
      and p.expires_at > now()
  ) stats on true
  left join lateral (
    select p.advertiser_type, p.title, p.governorate, p.city
    from public.properties p
    where p.owner_id = f.advertiser_id
      and p.status = 'published'
      and p.expires_at > now()
    order by p.created_at desc
    limit 1
  ) latest on true
  where f.follower_id = v_user
  order by f.created_at desc;
end;
$$;

revoke all on function public.follow_advertiser_from_property(uuid) from public, anon;
revoke all on function public.unfollow_advertiser(uuid) from public, anon;
revoke all on function public.get_followed_advertisers() from public, anon;
grant execute on function public.follow_advertiser_from_property(uuid) to authenticated;
grant execute on function public.unfollow_advertiser(uuid) to authenticated;
grant execute on function public.get_followed_advertisers() to authenticated;
