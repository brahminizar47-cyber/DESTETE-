-- DESTATE: safe public profile view for users followed by the signed-in account.
create or replace function public.get_followed_user_profile(p_user_id uuid)
returns table (
  display_name text,
  advertiser_type text,
  listing_count bigint,
  property_id uuid,
  title text,
  description text,
  property_type text,
  governorate text,
  city text,
  price numeric,
  area numeric,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_viewer uuid := auth.uid();
begin
  if v_viewer is null then
    raise exception 'AUTH_REQUIRED';
  end if;
  if not exists (
    select 1 from public.advertiser_follows f
    where f.follower_id = v_viewer and f.advertiser_id = p_user_id
  ) then
    raise exception 'USER_NOT_FOLLOWED';
  end if;

  return query
  select
    coalesce(
      nullif(btrim(u.raw_user_meta_data ->> 'display_name'), ''),
      nullif(btrim(u.raw_user_meta_data ->> 'full_name'), ''),
      nullif(btrim(u.raw_user_meta_data ->> 'name'), ''),
      'DESTATE user'
    )::text,
    coalesce(latest.advertiser_type, 'owner')::text,
    coalesce(stats.listing_count, 0)::bigint,
    p.id,
    p.title::text,
    p.description::text,
    p.property_type::text,
    p.governorate::text,
    p.city::text,
    p.price,
    p.area,
    p.created_at
  from auth.users u
  left join lateral (
    select count(*)::bigint as listing_count
    from public.properties x
    where x.owner_id = u.id
      and x.status = 'published'
      and x.expires_at > now()
  ) stats on true
  left join lateral (
    select x.advertiser_type
    from public.properties x
    where x.owner_id = u.id
      and x.status = 'published'
      and x.expires_at > now()
    order by x.created_at desc
    limit 1
  ) latest on true
  left join lateral (
    select x.id, x.title, x.description, x.property_type,
           x.governorate, x.city, x.price, x.area, x.created_at
    from public.properties x
    where x.owner_id = u.id
      and x.status = 'published'
      and x.expires_at > now()
    order by x.created_at desc
  ) p on true
  where u.id = p_user_id;
end;
$$;

revoke all on function public.get_followed_user_profile(uuid) from public, anon;
grant execute on function public.get_followed_user_profile(uuid) to authenticated;
