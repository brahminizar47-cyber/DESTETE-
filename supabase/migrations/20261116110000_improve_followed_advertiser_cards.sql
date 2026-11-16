-- Improve the authenticated user's followed-advertiser list with public display details.
drop function if exists public.get_followed_advertisers();

create function public.get_followed_advertisers()
returns table (
  advertiser_id uuid,
  display_name text,
  profile_photo_url text,
  advertiser_type text,
  listing_count bigint,
  latest_listing_title text,
  governorate text,
  city text,
  followed_at timestamptz
)
language plpgsql
stable
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
    coalesce(
      nullif(btrim(u.raw_user_meta_data ->> 'display_name'), ''),
      nullif(btrim(u.raw_user_meta_data ->> 'full_name'), ''),
      nullif(btrim(pr.full_name), '')
    )::text,
    nullif(btrim(u.raw_user_meta_data ->> 'profile_photo_url'), '')::text,
    coalesce(latest.advertiser_type, 'owner')::text,
    coalesce(stats.listing_count, 0)::bigint,
    latest.title::text,
    latest.governorate::text,
    latest.city::text,
    f.created_at
  from public.advertiser_follows f
  join auth.users u on u.id = f.advertiser_id
  left join public.profiles pr on pr.id = f.advertiser_id
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

  return found;
end;
$$;

revoke all on function public.get_followed_advertisers() from public, anon;
revoke all on function public.follow_advertiser_from_property(uuid) from public, anon;
grant execute on function public.get_followed_advertisers() to authenticated;
grant execute on function public.follow_advertiser_from_property(uuid) to authenticated;
