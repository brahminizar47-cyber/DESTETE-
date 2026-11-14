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
          'availability_status', p.availability_status,
          'rating_average', (select round(avg(prv.rating)::numeric, 1) from public.property_reviews prv where prv.property_id = p.id),
          'rating_count', (select count(*) from public.property_reviews prv where prv.property_id = p.id)
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


-- Property-specific reviews are separate from advertiser reviews.
create table if not exists public.property_reviews (
  id uuid primary key default gen_random_uuid(),
  property_id uuid not null references public.properties(id) on delete cascade,
  reviewer_id uuid not null references auth.users(id) on delete cascade,
  rating smallint not null check (rating between 1 and 5),
  comment varchar(150) not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint property_reviews_one_per_user unique (property_id, reviewer_id)
);

alter table public.property_reviews enable row level security;
revoke all on table public.property_reviews from anon, authenticated;

create or replace function public.get_property_reviews(p_property_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_owner_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  select p.owner_id into v_owner_id
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_owner_id is null then
    raise exception 'Published listing not found' using errcode = 'P0002';
  end if;

  return jsonb_build_object(
    'average_rating', (select round(avg(r.rating)::numeric, 1) from public.property_reviews r where r.property_id = p_property_id),
    'review_count', (select count(*) from public.property_reviews r where r.property_id = p_property_id),
    'can_review', (
      auth.uid() <> v_owner_id and exists (
        select 1 from public.property_contact_events e
        where e.requester_id = auth.uid()
          and e.property_id = p_property_id
          and e.advertiser_id = v_owner_id
      )
    ),
    'my_rating', (select r.rating from public.property_reviews r where r.property_id = p_property_id and r.reviewer_id = auth.uid()),
    'my_comment', (select r.comment from public.property_reviews r where r.property_id = p_property_id and r.reviewer_id = auth.uid()),
    'reviews', coalesce((
      select jsonb_agg(jsonb_build_object('rating', x.rating, 'comment', x.comment, 'created_at', x.created_at) order by x.created_at desc)
      from (select r.rating, r.comment, r.created_at from public.property_reviews r where r.property_id = p_property_id order by r.created_at desc limit 30) x
    ), '[]'::jsonb)
  );
end;
$function$;

create or replace function public.submit_property_review(p_property_id uuid, p_rating smallint, p_comment text default '')
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_owner_id uuid;
  v_review_id uuid;
  v_comment text := btrim(coalesce(p_comment, ''));
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_rating is null or p_rating < 1 or p_rating > 5 then
    raise exception 'Rating must be between 1 and 5' using errcode = '22023';
  end if;
  if char_length(v_comment) > 150 then
    raise exception 'Comment must be 150 characters or fewer' using errcode = '22023';
  end if;
  if not public.is_clean_review_comment(v_comment) then
    raise exception 'PROFANITY_BLOCKED' using errcode = '22023';
  end if;

  select p.owner_id into v_owner_id
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_owner_id is null then
    raise exception 'Published listing not found' using errcode = 'P0002';
  end if;
  if v_owner_id = auth.uid() then
    raise exception 'You cannot review your own listing' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.property_contact_events e
    where e.requester_id = auth.uid()
      and e.property_id = p_property_id
      and e.advertiser_id = v_owner_id
  ) then
    raise exception 'Contact the advertiser through DESTATE before reviewing this listing' using errcode = '42501';
  end if;

  perform private.enforce_action_rate_limit('review', 5, 86400);

  insert into public.property_reviews(property_id, reviewer_id, rating, comment)
  values (p_property_id, auth.uid(), p_rating, v_comment)
  on conflict (property_id, reviewer_id)
  do update set rating = excluded.rating, comment = excluded.comment, updated_at = now()
  returning id into v_review_id;

  return v_review_id;
end;
$function$;

revoke all on function public.get_property_reviews(uuid) from public, anon;
revoke all on function public.submit_property_review(uuid, smallint, text) from public, anon;
grant execute on function public.get_property_reviews(uuid) to authenticated;
grant execute on function public.submit_property_review(uuid, smallint, text) to authenticated;
