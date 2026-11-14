-- Enforce listing expiry at the database boundary.
drop policy if exists "Public can view published properties" on public.properties;
create policy "Public can view published properties"
on public.properties
for select
to anon, authenticated
using (status = 'published' and expires_at > now());

drop policy if exists "View images of published properties" on public.property_images;
create policy "View images of published properties"
on public.property_images
for select
to anon, authenticated
using (
  exists (
    select 1
    from public.properties p
    where p.id = property_images.property_id
      and p.status = 'published'
      and p.expires_at > now()
  )
);

create or replace function public.get_property_contact(p_property_id uuid)
returns text
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_phone text;
  v_advertiser_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  select c.phone, p.owner_id
    into v_phone, v_advertiser_id
  from private.property_contacts c
  join public.properties p on p.id = c.property_id
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_phone is null then
    raise exception 'Contact is unavailable' using errcode = 'P0002';
  end if;
  if v_advertiser_id = auth.uid() then
    raise exception 'You cannot contact yourself' using errcode = '42501';
  end if;

  perform private.enforce_action_rate_limit('contact', 10, 3600);

  insert into public.property_contact_events(property_id, advertiser_id, requester_id)
  values (p_property_id, v_advertiser_id, auth.uid());

  return v_phone;
end;
$function$;

create or replace function public.get_advertiser_reviews(p_property_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path to ''
as $function$
declare
  v_advertiser_id uuid;
  v_result jsonb;
begin
  select p.owner_id into v_advertiser_id
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_advertiser_id is null then
    raise exception 'Listing not found' using errcode = 'P0002';
  end if;

  select jsonb_build_object(
    'average_rating', (select round(avg(r.rating)::numeric, 1) from public.advertiser_reviews r where r.advertiser_id = v_advertiser_id),
    'review_count', (select count(*) from public.advertiser_reviews r where r.advertiser_id = v_advertiser_id),
    'can_review', (auth.uid() is not null and auth.uid() <> v_advertiser_id and exists (
      select 1 from public.property_contact_events e
      where e.requester_id = auth.uid() and e.advertiser_id = v_advertiser_id and e.property_id = p_property_id
    )),
    'my_rating', (select r.rating from public.advertiser_reviews r where r.advertiser_id = v_advertiser_id and r.reviewer_id = auth.uid()),
    'my_comment', (select r.comment from public.advertiser_reviews r where r.advertiser_id = v_advertiser_id and r.reviewer_id = auth.uid()),
    'reviews', coalesce((
      select jsonb_agg(jsonb_build_object('id', x.id, 'rating', x.rating, 'comment', x.comment, 'created_at', x.created_at) order by x.created_at desc)
      from (
        select r.id, r.rating, r.comment, r.created_at
        from public.advertiser_reviews r
        where r.advertiser_id = v_advertiser_id
        order by r.created_at desc
        limit 30
      ) x
    ), '[]'::jsonb)
  ) into v_result;
  return v_result;
end;
$function$;

create or replace function public.submit_advertiser_review(
  p_property_id uuid,
  p_rating smallint,
  p_comment text default ''
)
returns uuid
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_advertiser_id uuid;
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

  select p.owner_id into v_advertiser_id
  from public.properties p
  where p.id = p_property_id
    and p.status = 'published'
    and p.expires_at > now();

  if v_advertiser_id is null then
    raise exception 'Listing not found' using errcode = 'P0002';
  end if;
  if v_advertiser_id = auth.uid() then
    raise exception 'You cannot review yourself' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.property_contact_events e
    where e.requester_id = auth.uid()
      and e.advertiser_id = v_advertiser_id
      and e.property_id = p_property_id
  ) then
    raise exception 'Contact the advertiser through DESTATE before reviewing'
      using errcode = '42501';
  end if;

  perform private.enforce_action_rate_limit('review', 5, 86400);

  insert into public.advertiser_reviews(advertiser_id, reviewer_id, rating, comment)
  values (v_advertiser_id, auth.uid(), p_rating, v_comment)
  on conflict (advertiser_id, reviewer_id)
  do update set
    rating = excluded.rating,
    comment = excluded.comment,
    updated_at = now()
  returning id into v_review_id;

  return v_review_id;
end;
$function$;
