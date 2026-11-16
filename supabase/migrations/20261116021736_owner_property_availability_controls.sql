drop function if exists public.get_my_property_stats();
create function public.get_my_property_stats()
returns table(property_id uuid,title text,price numeric,price_type text,area numeric,area_unit text,status text,availability_status text,expires_at timestamptz,updated_at timestamptz,view_count bigint,contact_count bigint,favorite_count bigint)
language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  return query
  select p.id,p.title,p.price,p.price_type,p.area,p.area_unit,p.status,p.availability_status,p.expires_at,p.updated_at,
    (select count(*) from private.property_view_events v where v.property_id=p.id),
    (select count(*) from public.property_contact_events c where c.property_id=p.id),
    (select count(*) from public.property_favorites f where f.property_id=p.id)
  from public.properties p where p.owner_id=v_uid order by p.created_at desc;
end;
$$;
revoke all on function public.get_my_property_stats() from public, anon;
grant execute on function public.get_my_property_stats() to authenticated;

create or replace function public.set_property_availability(p_property_id uuid,p_availability_status text)
returns text language plpgsql security definer set search_path = '' as $$
declare v_status text;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_availability_status not in ('available','sold','rented') then raise exception 'INVALID_AVAILABILITY_STATUS' using errcode='22023'; end if;
  update public.properties
  set availability_status=p_availability_status,
      availability_confirmed_at=case when p_availability_status='available' then now() else availability_confirmed_at end,
      updated_at=now()
  where id=p_property_id and owner_id=auth.uid() and status='published'
  returning availability_status into v_status;
  if v_status is null then raise exception 'PROPERTY_NOT_FOUND_OR_NOT_OWNED'; end if;
  return v_status;
end;
$$;
revoke all on function public.set_property_availability(uuid,text) from public, anon;
grant execute on function public.set_property_availability(uuid,text) to authenticated;
