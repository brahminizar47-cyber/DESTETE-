-- DESTATE abuse protection, private admin audit trail, and paginated report review.
-- Additive migration: no existing user content is removed.

-- Per-user/action counters. The private schema is not exposed through the Data API.
create table if not exists private.action_rate_limits (
  user_id uuid not null references auth.users(id) on delete cascade,
  action text not null check (action in ('contact', 'review', 'report')),
  window_started_at timestamptz not null,
  request_count integer not null check (request_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (user_id, action)
);

alter table private.action_rate_limits enable row level security;
revoke all on table private.action_rate_limits from public, anon, authenticated;

create or replace function private.enforce_action_rate_limit(
  p_action text,
  p_max_requests integer,
  p_window_seconds integer
)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $function$
declare
  v_user_id uuid := auth.uid();
  v_now timestamptz := clock_timestamp();
  v_count integer;
begin
  if v_user_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_action not in ('contact', 'review', 'report')
     or p_max_requests < 1
     or p_window_seconds < 1
     or p_window_seconds > 86400 then
    raise exception 'Invalid rate limit configuration' using errcode = '22023';
  end if;

  insert into private.action_rate_limits as current_limit
    (user_id, action, window_started_at, request_count, updated_at)
  values
    (v_user_id, p_action, v_now, 1, v_now)
  on conflict (user_id, action) do update
  set
    window_started_at = case
      when current_limit.window_started_at <= v_now - make_interval(secs => p_window_seconds)
      then v_now else current_limit.window_started_at end,
    request_count = case
      when current_limit.window_started_at <= v_now - make_interval(secs => p_window_seconds)
      then 1 else current_limit.request_count + 1 end,
    updated_at = v_now
  returning request_count into v_count;

  if v_count > p_max_requests then
    raise exception 'RATE_LIMITED:%', p_action using errcode = 'P0001';
  end if;
end;
$function$;

revoke all on function private.enforce_action_rate_limit(text, integer, integer)
  from public, anon, authenticated;

-- Limit successful contact reveals to 10 per user per rolling hour.
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
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  select c.phone, p.owner_id
    into v_phone, v_advertiser_id
  from private.property_contacts c
  join public.properties p on p.id = c.property_id
  where p.id = p_property_id and p.status = 'published';

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

-- Limit review submissions/edits to 5 per user per rolling day.
create or replace function public.submit_advertiser_review(
  p_property_id uuid,
  p_rating smallint,
  p_comment text default ''
)
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
  where p.id = p_property_id and p.status = 'published';

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

-- Limit complaint submissions to 5 per user per rolling hour.
create or replace function public.submit_platform_report(
  p_target_type text,
  p_property_id uuid default null,
  p_target_id uuid default null,
  p_details text default ''
)
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
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_target_type not in ('listing', 'advertiser', 'review', 'technical', 'other') then
    raise exception 'Invalid report category' using errcode = '22023';
  end if;
  if v_details = '' or char_length(v_details) > 1000 then
    raise exception 'Report details must be between 1 and 1000 characters'
      using errcode = '22023';
  end if;

  if p_target_type in ('listing', 'advertiser', 'review') then
    if p_property_id is null then
      raise exception 'A related listing is required' using errcode = '22023';
    end if;
    select p.owner_id into v_owner_id
    from public.properties p
    where p.id = p_property_id;
    if v_owner_id is null then
      raise exception 'Listing not found' using errcode = 'P0002';
    end if;
  end if;

  if p_target_type = 'review' then
    if p_target_id is null or not exists (
      select 1 from public.advertiser_reviews r
      where r.id = p_target_id and r.advertiser_id = v_owner_id
    ) then
      raise exception 'Review not found for this advertiser' using errcode = 'P0002';
    end if;
  elsif p_target_id is not null then
    raise exception 'Unexpected target ID' using errcode = '22023';
  end if;

  perform private.enforce_action_rate_limit('report', 5, 3600);

  insert into public.platform_reports(reporter_id, target_type, property_id, target_id, details)
  values (auth.uid(), p_target_type, p_property_id, p_target_id, v_details)
  returning id into v_report_id;

  return v_report_id;
end;
$function$;

-- Private audit log. Actor IDs are retained as UUIDs, without exposing email/phone data.
create table if not exists private.admin_action_logs (
  id bigint generated always as identity primary key,
  actor_id uuid not null,
  action text not null check (
    action in ('listing_status_changed', 'listing_deleted', 'report_status_changed')
  ),
  entity_type text not null check (entity_type in ('property', 'report')),
  entity_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists admin_action_logs_created_at_idx
  on private.admin_action_logs(created_at desc);
create index if not exists admin_action_logs_entity_idx
  on private.admin_action_logs(entity_type, entity_id, created_at desc);

alter table private.admin_action_logs enable row level security;
revoke all on table private.admin_action_logs from public, anon, authenticated;

create or replace function private.capture_admin_property_action()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if auth.uid() is null or not public.is_admin() then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;

  if tg_op = 'UPDATE' then
    if old.status is distinct from new.status then
      insert into private.admin_action_logs(
        actor_id, action, entity_type, entity_id, details
      )
      values (
        auth.uid(),
        'listing_status_changed',
        'property',
        new.id,
        jsonb_build_object(
          'title', new.title,
          'from_status', old.status,
          'to_status', new.status
        )
      );
    end if;
    return new;
  elsif tg_op = 'DELETE' then
    insert into private.admin_action_logs(
      actor_id, action, entity_type, entity_id, details
    )
    values (
      auth.uid(),
      'listing_deleted',
      'property',
      old.id,
      jsonb_build_object(
        'title', old.title,
        'previous_status', old.status
      )
    );
    return old;
  end if;

  return null;
end;
$function$;

revoke all on function private.capture_admin_property_action()
  from public, anon, authenticated;

drop trigger if exists destate_admin_action_audit on public.properties;
create trigger destate_admin_action_audit
after update of status or delete on public.properties
for each row execute function private.capture_admin_property_action();

-- Add filtered, bounded pagination for the admin reports queue.
drop function if exists public.admin_list_platform_reports();

create or replace function public.admin_list_platform_reports(
  p_limit integer default 20,
  p_offset integer default 0,
  p_status text default null,
  p_target_type text default null,
  p_search text default null
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_items jsonb;
  v_total bigint;
  v_search text := nullif(btrim(p_search), '');
begin
  if not public.is_admin() then
    raise exception 'Administrator access required' using errcode = '42501';
  end if;
  if p_limit < 1 or p_limit > 50 or p_offset < 0 or p_offset > 10000 then
    raise exception 'Invalid pagination values' using errcode = '22023';
  end if;
  if p_status is not null and p_status not in ('pending', 'reviewing', 'resolved', 'rejected') then
    raise exception 'Invalid report status filter' using errcode = '22023';
  end if;
  if p_target_type is not null and p_target_type not in ('listing', 'advertiser', 'review', 'technical', 'other') then
    raise exception 'Invalid report category filter' using errcode = '22023';
  end if;
  if v_search is not null and char_length(v_search) > 100 then
    raise exception 'Search text is too long' using errcode = '22023';
  end if;

  select count(*) into v_total
  from public.platform_reports r
  where (p_status is null or r.status = p_status)
    and (p_target_type is null or r.target_type = p_target_type)
    and (
      v_search is null
      or r.details ilike '%' || v_search || '%'
      or r.id::text ilike '%' || v_search || '%'
      or r.property_id::text ilike '%' || v_search || '%'
    );

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', page.id,
        'target_type', page.target_type,
        'property_id', page.property_id,
        'target_id', page.target_id,
        'details', page.details,
        'status', page.status,
        'created_at', page.created_at
      ) order by page.created_at desc
    ),
    '[]'::jsonb
  ) into v_items
  from (
    select r.id, r.target_type, r.property_id, r.target_id,
      r.details, r.status, r.created_at
    from public.platform_reports r
    where (p_status is null or r.status = p_status)
      and (p_target_type is null or r.target_type = p_target_type)
      and (
        v_search is null
        or r.details ilike '%' || v_search || '%'
        or r.id::text ilike '%' || v_search || '%'
        or r.property_id::text ilike '%' || v_search || '%'
      )
    order by r.created_at desc
    limit p_limit offset p_offset
  ) page;

  return jsonb_build_object(
    'items', v_items,
    'total_count', v_total,
    'limit', p_limit,
    'offset', p_offset
  );
end;
$function$;

-- Record report status changes, and expose the private audit trail only to admins.
create or replace function public.admin_update_platform_report(p_report_id uuid, p_status text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_old_status text;
  v_target_type text;
begin
  if not public.is_admin() then
    raise exception 'Administrator access required' using errcode = '42501';
  end if;
  if p_status not in ('reviewing', 'resolved', 'rejected') then
    raise exception 'Invalid report status' using errcode = '22023';
  end if;

  select r.status, r.target_type
    into v_old_status, v_target_type
  from public.platform_reports r
  where r.id = p_report_id
  for update;

  if not found then
    return false;
  end if;

  if v_old_status is distinct from p_status then
    update public.platform_reports
      set status = p_status, updated_at = now()
    where id = p_report_id;

    insert into private.admin_action_logs(
      actor_id, action, entity_type, entity_id, details
    )
    values (
      auth.uid(),
      'report_status_changed',
      'report',
      p_report_id,
      jsonb_build_object(
        'target_type', v_target_type,
        'from_status', v_old_status,
        'to_status', p_status
      )
    );
  end if;

  return true;
end;
$function$;

create or replace function public.admin_list_action_logs(
  p_limit integer default 50,
  p_offset integer default 0
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_items jsonb;
begin
  if not public.is_admin() then
    raise exception 'Administrator access required' using errcode = '42501';
  end if;
  if p_limit < 1 or p_limit > 100 or p_offset < 0 or p_offset > 10000 then
    raise exception 'Invalid pagination values' using errcode = '22023';
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', page.id,
        'actor_id', page.actor_id,
        'action', page.action,
        'entity_type', page.entity_type,
        'entity_id', page.entity_id,
        'details', page.details,
        'created_at', page.created_at
      ) order by page.created_at desc
    ),
    '[]'::jsonb
  ) into v_items
  from (
    select l.id, l.actor_id, l.action, l.entity_type, l.entity_id, l.details, l.created_at
    from private.admin_action_logs l
    order by l.created_at desc
    limit p_limit offset p_offset
  ) page;

  return v_items;
end;
$function$;

-- Restrict RPC execution explicitly. Existing callers remain authenticated-only.
revoke all on function public.get_property_contact(uuid) from public, anon;
grant execute on function public.get_property_contact(uuid) to authenticated;

revoke all on function public.submit_advertiser_review(uuid, smallint, text) from public, anon;
grant execute on function public.submit_advertiser_review(uuid, smallint, text) to authenticated;

revoke all on function public.submit_platform_report(text, uuid, uuid, text) from public, anon;
grant execute on function public.submit_platform_report(text, uuid, uuid, text) to authenticated;

revoke all on function public.admin_list_platform_reports(integer, integer, text, text, text)
  from public, anon;
grant execute on function public.admin_list_platform_reports(integer, integer, text, text, text)
  to authenticated;

revoke all on function public.admin_update_platform_report(uuid, text) from public, anon;
grant execute on function public.admin_update_platform_report(uuid, text) to authenticated;

revoke all on function public.admin_list_action_logs(integer, integer) from public, anon;
grant execute on function public.admin_list_action_logs(integer, integer) to authenticated;
