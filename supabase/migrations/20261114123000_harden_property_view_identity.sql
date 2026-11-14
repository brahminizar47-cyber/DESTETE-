-- Prevent authenticated clients from spoofing another visitor's identity.
-- Anonymous view tracking remains best-effort because browsers cannot provide
-- a server-verifiable identity without a signed session/token.
create or replace function public.record_property_view(
  p_property_id uuid,
  p_visitor_id uuid
)
returns boolean
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_visitor_id uuid := coalesce(auth.uid(), p_visitor_id);
begin
  if p_property_id is null or v_visitor_id is null then
    return false;
  end if;

  if not exists (
    select 1
    from public.properties p
    where p.id = p_property_id
      and p.status = 'published'
      and p.expires_at > now()
  ) then
    return false;
  end if;

  insert into private.property_view_events(property_id, visitor_id, viewed_on)
  values (p_property_id, v_visitor_id, current_date)
  on conflict (property_id, visitor_id, viewed_on) do nothing;

  return true;
end;
$function$;