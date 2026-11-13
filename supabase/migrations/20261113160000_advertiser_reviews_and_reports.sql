-- DESTATE advertiser reviews, contact evidence, and private complaint workflow.
-- Apply only after reviewing the matching frontend PR.

create table if not exists public.property_contact_events (
  id uuid primary key default gen_random_uuid(),
  property_id uuid not null references public.properties(id) on delete cascade,
  advertiser_id uuid not null references auth.users(id) on delete cascade,
  requester_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists property_contact_events_requester_advertiser_idx
  on public.property_contact_events(requester_id, advertiser_id, property_id);
alter table public.property_contact_events enable row level security;

create table if not exists public.advertiser_reviews (
  id uuid primary key default gen_random_uuid(),
  advertiser_id uuid not null references auth.users(id) on delete cascade,
  reviewer_id uuid not null references auth.users(id) on delete cascade,
  rating smallint not null check (rating between 1 and 5),
  comment varchar(150) not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint advertiser_reviews_one_per_user unique (advertiser_id, reviewer_id),
  constraint advertiser_reviews_no_self check (advertiser_id <> reviewer_id)
);
create index if not exists advertiser_reviews_advertiser_idx
  on public.advertiser_reviews(advertiser_id, created_at desc);
alter table public.advertiser_reviews enable row level security;

create table if not exists public.platform_reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete cascade,
  target_type text not null check (target_type in ('listing','advertiser','review','technical','other')),
  property_id uuid references public.properties(id) on delete set null,
  target_id uuid,
  details varchar(1000) not null,
  status text not null default 'pending' check (status in ('pending','reviewing','resolved','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists platform_reports_status_created_idx
  on public.platform_reports(status, created_at desc);
create index if not exists platform_reports_reporter_created_idx
  on public.platform_reports(reporter_id, created_at desc);
alter table public.platform_reports enable row level security;

create or replace function public.is_clean_review_comment(p_comment text)
returns boolean
language plpgsql
immutable
set search_path = ''
as $function$
declare
  v_compact text;
  v_term text;
  v_terms text[] := array[
    'fuck','shit','bitch','asshole','bastard','motherfucker',
    'merde','putain','connard','connasse','salope','encule',
    'كس','قحبة','شرموط','منيوك','زبي','طيز','متناك'
  ];
begin
  if p_comment is null or btrim(p_comment) = '' then return true; end if;
  v_compact := regexp_replace(lower(normalize(p_comment, NFKC)), '[^[:alnum:]]', '', 'g');
  v_compact := translate(v_compact, 'ًٌٍَُِّْـٰ', '');
  foreach v_term in array v_terms loop
    if v_term <> '' and strpos(v_compact, v_term) > 0 then return false; end if;
  end loop;
  return true;
end;
$function$;

create or replace function public.get_property_contact(p_property_id uuid)
returns text
language plpgsql
volatile
security definer
set search_path = ''
as $function$
declare
  v_phone text;
  v_advertiser_id uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  select c.phone, p.owner_id into v_phone, v_advertiser_id
  from private.property_contacts c
  join public.properties p on p.id = c.property_id
  where p.id = p_property_id and p.status = 'published';
  if v_phone is null then raise exception 'Contact is unavailable' using errcode = 'P0002'; end if;
  if v_advertiser_id = auth.uid() then raise exception 'You cannot contact yourself' using errcode = '42501'; end if;
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
set search_path = ''
as $function$
declare
  v_advertiser_id uuid;
  v_result jsonb;
begin
  select p.owner_id into v_advertiser_id from public.properties p
  where p.id = p_property_id and p.status = 'published';
  if v_advertiser_id is null then raise exception 'Listing not found' using errcode = 'P0002'; end if;
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
      from (select r.id, r.rating, r.comment, r.created_at from public.advertiser_reviews r
        where r.advertiser_id = v_advertiser_id order by r.created_at desc limit 30) x
    ), '[]'::jsonb)
  ) into v_result;
  return v_result;
end;
$function$;

create or replace function public.submit_advertiser_review(p_property_id uuid, p_rating smallint, p_comment text default '')
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_advertiser_id uuid;
  v_review_id uuid;
  v_comment text := btrim(coalesce(p_comment, ''));
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if p_rating is null or p_rating < 1 or p_rating > 5 then raise exception 'Rating must be between 1 and 5' using errcode = '22023'; end if;
  if char_length(v_comment) > 150 then raise exception 'Comment must be 150 characters or fewer' using errcode = '22023'; end if;
  if not public.is_clean_review_comment(v_comment) then raise exception 'PROFANITY_BLOCKED' using errcode = '22023'; end if;
  select p.owner_id into v_advertiser_id from public.properties p where p.id = p_property_id and p.status = 'published';
  if v_advertiser_id is null then raise exception 'Listing not found' using errcode = 'P0002'; end if;
  if v_advertiser_id = auth.uid() then raise exception 'You cannot review yourself' using errcode = '42501'; end if;
  if not exists (select 1 from public.property_contact_events e
    where e.requester_id = auth.uid() and e.advertiser_id = v_advertiser_id and e.property_id = p_property_id) then
    raise exception 'Contact the advertiser through DESTATE before reviewing' using errcode = '42501';
  end if;
  insert into public.advertiser_reviews(advertiser_id, reviewer_id, rating, comment)
  values (v_advertiser_id, auth.uid(), p_rating, v_comment)
  on conflict (advertiser_id, reviewer_id)
  do update set rating = excluded.rating, comment = excluded.comment, updated_at = now()
  returning id into v_review_id;
  return v_review_id;
end;
$function$;

create or replace function public.submit_platform_report(p_target_type text, p_property_id uuid default null, p_target_id uuid default null, p_details text default '')
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_report_id uuid;
  v_details text := btrim(coalesce(p_details, ''));
  v_owner_id uuid;
begin
  if auth.uid() is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if p_target_type not in ('listing','advertiser','review','technical','other') then raise exception 'Invalid report category' using errcode = '22023'; end if;
  if v_details = '' or char_length(v_details) > 1000 then raise exception 'Report details must be between 1 and 1000 characters' using errcode = '22023'; end if;
  if p_target_type in ('listing','advertiser','review') then
    if p_property_id is null then raise exception 'A related listing is required' using errcode = '22023'; end if;
    select p.owner_id into v_owner_id from public.properties p where p.id = p_property_id;
    if v_owner_id is null then raise exception 'Listing not found' using errcode = 'P0002'; end if;
  end if;
  if p_target_type = 'review' then
    if p_target_id is null or not exists (select 1 from public.advertiser_reviews r where r.id = p_target_id and r.advertiser_id = v_owner_id) then
      raise exception 'Review not found for this advertiser' using errcode = 'P0002';
    end if;
  elsif p_target_id is not null then
    raise exception 'Unexpected target ID' using errcode = '22023';
  end if;
  insert into public.platform_reports(reporter_id, target_type, property_id, target_id, details)
  values (auth.uid(), p_target_type, p_property_id, p_target_id, v_details)
  returning id into v_report_id;
  return v_report_id;
end;
$function$;

create or replace function public.my_platform_reports()
returns jsonb language sql stable security definer set search_path = ''
as $function$
  select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'target_type', r.target_type,
    'details', r.details, 'status', r.status, 'created_at', r.created_at) order by r.created_at desc), '[]'::jsonb)
  from public.platform_reports r where r.reporter_id = auth.uid();
$function$;

create or replace function public.admin_list_platform_reports()
returns jsonb language plpgsql stable security definer set search_path = ''
as $function$
begin
  if not public.is_admin() then raise exception 'Administrator access required' using errcode = '42501'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'reporter_id', r.reporter_id,
    'target_type', r.target_type, 'property_id', r.property_id, 'target_id', r.target_id,
    'details', r.details, 'status', r.status, 'created_at', r.created_at) order by r.created_at desc)
    from public.platform_reports r), '[]'::jsonb);
end;
$function$;

create or replace function public.admin_update_platform_report(p_report_id uuid, p_status text)
returns boolean language plpgsql security definer set search_path = ''
as $function$
begin
  if not public.is_admin() then raise exception 'Administrator access required' using errcode = '42501'; end if;
  if p_status not in ('reviewing','resolved','rejected') then raise exception 'Invalid report status' using errcode = '22023'; end if;
  update public.platform_reports set status = p_status, updated_at = now() where id = p_report_id;
  return found;
end;
$function$;

revoke all on public.property_contact_events, public.advertiser_reviews, public.platform_reports from anon, authenticated;
revoke all on function public.is_clean_review_comment(text) from public, anon, authenticated;
revoke all on function public.get_property_contact(uuid) from public, anon;
revoke all on function public.get_advertiser_reviews(uuid) from public;
revoke all on function public.submit_advertiser_review(uuid, smallint, text) from public, anon;
revoke all on function public.submit_platform_report(text, uuid, uuid, text) from public, anon;
revoke all on function public.my_platform_reports() from public, anon;
revoke all on function public.admin_list_platform_reports() from public, anon;
revoke all on function public.admin_update_platform_report(uuid, text) from public, anon;
grant execute on function public.get_property_contact(uuid) to authenticated;
grant execute on function public.get_advertiser_reviews(uuid) to anon, authenticated;
grant execute on function public.submit_advertiser_review(uuid, smallint, text) to authenticated;
grant execute on function public.submit_platform_report(text, uuid, uuid, text) to authenticated;
grant execute on function public.my_platform_reports() to authenticated;
grant execute on function public.admin_list_platform_reports() to authenticated;
grant execute on function public.admin_update_platform_report(uuid, text) to authenticated;
