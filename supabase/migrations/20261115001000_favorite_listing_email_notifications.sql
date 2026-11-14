-- DESTATE: queue and deliver email alerts for changes to favorited listings.
-- Existing in-app notifications remain unchanged; this adds durable email delivery.

create extension if not exists pg_cron with schema pg_catalog;
create extension if not exists pg_net;

create table if not exists private.favorite_listing_email_queue (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references auth.users(id) on delete cascade,
  property_id uuid not null references public.properties(id) on delete cascade,
  property_title text not null,
  notification_title text not null,
  notification_body text not null,
  created_at timestamptz not null default now(),
  attempts integer not null default 0 check (attempts >= 0),
  locked_until timestamptz,
  sent_at timestamptz,
  last_error text
);

create index if not exists favorite_listing_email_queue_pending_idx
  on private.favorite_listing_email_queue (created_at)
  where sent_at is null;

alter table private.favorite_listing_email_queue enable row level security;
revoke all on private.favorite_listing_email_queue from public, anon, authenticated;

create or replace function public.claim_favorite_listing_email_batch(p_limit integer default 25)
returns table (
  queue_id uuid,
  recipient_email text,
  property_title text,
  notification_title text,
  notification_body text,
  property_id uuid,
  attempts integer
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query
  with picked as (
    select q.id
    from private.favorite_listing_email_queue q
    where q.sent_at is null
      and q.attempts < 5
      and (q.locked_until is null or q.locked_until < pg_catalog.now())
    order by q.created_at
    for update skip locked
    limit greatest(1, least(coalesce(p_limit, 25), 50))
  ),
  claimed as (
    update private.favorite_listing_email_queue q
    set attempts = q.attempts + 1,
        locked_until = pg_catalog.now() + interval '10 minutes'
    from picked p
    where q.id = p.id
    returning q.id, q.recipient_id, q.property_id, q.property_title,
              q.notification_title, q.notification_body, q.attempts
  )
  select c.id, u.email::text, c.property_title, c.notification_title,
         c.notification_body, c.property_id, c.attempts
  from claimed c
  left join auth.users u on u.id = c.recipient_id;
end;
$$;

create or replace function public.complete_favorite_listing_email(p_queue_id uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  update private.favorite_listing_email_queue
  set sent_at = pg_catalog.now(), locked_until = null, last_error = null
  where id = p_queue_id and sent_at is null;
$$;

create or replace function public.fail_favorite_listing_email(p_queue_id uuid, p_error text)
returns void
language sql
security definer
set search_path = ''
as $$
  update private.favorite_listing_email_queue
  set locked_until = null, last_error = left(coalesce(p_error, 'Unknown email error'), 1000)
  where id = p_queue_id and sent_at is null;
$$;

revoke all on function public.claim_favorite_listing_email_batch(integer) from public, anon, authenticated;
revoke all on function public.complete_favorite_listing_email(uuid) from public, anon, authenticated;
revoke all on function public.fail_favorite_listing_email(uuid, text) from public, anon, authenticated;
grant execute on function public.claim_favorite_listing_email_batch(integer) to service_role;
grant execute on function public.complete_favorite_listing_email(uuid) to service_role;
grant execute on function public.fail_favorite_listing_email(uuid, text) to service_role;

create or replace function public.notify_favorited_property_changes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_title text;
  v_body text;
begin
  if new.price is distinct from old.price then
    v_title := 'تغيير سعر عقار محفوظ';
    v_body := 'تغيّر سعر عقار أضفته إلى المفضّلة.';
  elsif new.ownership_type is distinct from old.ownership_type then
    v_title := 'تحديث نوع ملكية عقار محفوظ';
    v_body := 'تم تحديث نوع ملكية عقار أضفته إلى المفضّلة.';
  elsif new.availability_status is distinct from old.availability_status
     or new.status is distinct from old.status then
    v_title := 'تحديث حالة عقار محفوظ';
    v_body := 'تم تحديث حالة عقار أضفته إلى المفضّلة.';
  elsif new.image_urls is distinct from old.image_urls then
    v_title := 'تحديث صور عقار محفوظ';
    v_body := 'تم تحديث صور عقار أضفته إلى المفضّلة.';
  else
    return new;
  end if;

  insert into public.user_notifications
    (recipient_id, notification_type, title, body, property_id)
  select f.user_id, 'favorite_listing_update', v_title, v_body, new.id
  from public.property_favorites f
  where f.property_id = new.id
    and f.user_id <> new.owner_id;

  insert into private.favorite_listing_email_queue
    (recipient_id, property_id, property_title, notification_title, notification_body)
  select f.user_id, new.id, new.title, v_title, v_body
  from public.property_favorites f
  where f.property_id = new.id
    and f.user_id <> new.owner_id;

  return new;
end;
$$;

drop trigger if exists favorited_property_update_notification on public.properties;
create trigger favorited_property_update_notification
after update of price, ownership_type, availability_status, status, image_urls
on public.properties
for each row execute function public.notify_favorited_property_changes();

-- The job remains idle until both Vault secrets are configured.
select cron.schedule(
  'destate-favorite-listing-email-worker',
  '* * * * *',
  $job$
    select net.http_post(
      url := (select decrypted_secret from vault.decrypted_secrets where name = 'destate_email_worker_url'),
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' ||
          (select decrypted_secret from vault.decrypted_secrets where name = 'destate_email_worker_secret')
      ),
      body := '{}'::jsonb,
      timeout_milliseconds := 10000
    )
    where exists (select 1 from vault.decrypted_secrets where name = 'destate_email_worker_url')
      and exists (select 1 from vault.decrypted_secrets where name = 'destate_email_worker_secret');
  $job$
);
