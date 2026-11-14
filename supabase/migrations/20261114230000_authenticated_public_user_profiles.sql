-- Public user profile data is available only to signed-in users.
-- The function accepts a published listing ID, never a user UUID from the browser,
-- and returns an explicit allowlist of public fields only.

create or replace function public.get_public_user_profile(p_property_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_user_id uuid;
  v_result jsonb;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  select p.owner_id
    into v_user_id
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_user_id is null then
    raise exception 'Published listing not found' using errcode = 'P0002';
  end if;

  select jsonb_build_object(
    'profile', jsonb_build_object(
      'display_name', coalesce(
        nullif(btrim(u.raw_user_meta_data ->> 'display_name'), ''),
        nullif(btrim(u.raw_user_meta_data ->> 'full_name'), ''),
        nullif(btrim(pr.full_name), ''),
        null
      ),
      'advertiser_type', (
        select p2.advertiser_type
        from public.properties p2
        where p2.owner_id = v_user_id
          and p2.status = 'published'
          and p2.expires_at > now()
        order by p2.created_at desc
        limit 1
      )
    ),
    'average_rating', (
      select round(avg(r.rating)::numeric, 1)
      from public.advertiser_reviews r
      where r.advertiser_id = v_user_id
    ),
    'review_count', (
      select count(*)
      from public.advertiser_reviews r
      where r.advertiser_id = v_user_id
    ),
    'listings', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id', p.id,
          'title', p.title,
          'description', p.description,
          'property_type', p.property_type,
          'governorate', p.governorate,
          'city', p.city,
          'price', p.price,
          'area', p.area,
          'image_urls', p.image_urls,
          'created_at', p.created_at,
          'availability_status', p.availability_status
        ) order by p.created_at desc
      )
      from public.properties p
      where p.owner_id = v_user_id
        and p.status = 'published'
        and p.expires_at > now()
    ), '[]'::jsonb),
    'reviews', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'rating', r.rating,
          'comment', r.comment,
          'created_at', r.created_at
        ) order by r.created_at desc
      )
      from (
        select ar.rating, ar.comment, ar.created_at
        from public.advertiser_reviews ar
        where ar.advertiser_id = v_user_id
        order by ar.created_at desc
        limit 50
      ) r
    ), '[]'::jsonb)
  )
  into v_result
  from auth.users u
  left join public.profiles pr on pr.id = u.id
  where u.id = v_user_id;

  return v_result;
end;
$function$;

revoke all on function public.get_public_user_profile(uuid) from public;
revoke all on function public.get_public_user_profile(uuid) from anon;
grant execute on function public.get_public_user_profile(uuid) to authenticated;

-- Reviews must not be retrievable by anonymous visitors.
revoke all on function public.get_advertiser_reviews(uuid) from public;
revoke all on function public.get_advertiser_reviews(uuid) from anon;
grant execute on function public.get_advertiser_reviews(uuid) to authenticated;
