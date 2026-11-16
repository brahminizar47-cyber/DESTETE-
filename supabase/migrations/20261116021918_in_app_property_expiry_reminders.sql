alter table public.properties add column availability_reminder_sent_at timestamptz;

create or replace function private.notify_property_expiring_owners()
returns integer language plpgsql security definer set search_path = '' as $$
declare v_count integer := 0;
begin
  with due as (
    select p.id,p.owner_id from public.properties p
    where p.status='published' and p.availability_status='available'
      and p.expires_at > pg_catalog.now()
      and p.expires_at <= pg_catalog.now() + interval '3 days'
      and p.availability_reminder_sent_at is null
    for update skip locked
  ), notified as (
    insert into public.user_notifications(recipient_id,notification_type,title,body,property_id)
    select d.owner_id,'property_expiry_reminder',
      'تذكير بتأكيد توفر عقارك',
      'ينتهي ظهور أحد إعلاناتك خلال 3 أيام. أكّد توفره أو حدّث حالته من صفحة إعلاناتي.',
      d.id
    from due d returning property_id
  )
  update public.properties p set availability_reminder_sent_at=pg_catalog.now()
  from notified n where p.id=n.property_id;
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;
revoke all on function private.notify_property_expiring_owners() from public, anon, authenticated;

create or replace function public.confirm_property_availability(p_property_id uuid)
returns timestamptz language plpgsql security definer set search_path = '' as $$
declare v_expires_at timestamptz;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  update public.properties
  set availability_status='available',
      availability_confirmed_at=pg_catalog.now(),
      availability_reminder_sent_at=null,
      expires_at=pg_catalog.now()+interval '30 days'
  where id=p_property_id and owner_id=auth.uid() and status='published'
  returning expires_at into v_expires_at;
  if v_expires_at is null then raise exception 'PROPERTY_NOT_FOUND_OR_NOT_OWNED'; end if;
  return v_expires_at;
end;
$$;
revoke all on function public.confirm_property_availability(uuid) from public, anon;
grant execute on function public.confirm_property_availability(uuid) to authenticated;

select cron.unschedule(jobid) from cron.job where jobname='destate-property-expiry-reminders';
select cron.schedule('destate-property-expiry-reminders','0 8 * * *','select private.notify_property_expiring_owners();');
