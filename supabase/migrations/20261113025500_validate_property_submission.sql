-- Validate authenticated property submissions at the database boundary.
-- This complements browser validation; callers cannot bypass required listing fields via RPC.

create or replace function public.create_property_with_contact(
  p_property jsonb,
  p_phone text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_user_id uuid := auth.uid();
  v_property_id uuid;
  v_property_type text;
  v_advertiser_type text;
  v_ownership_type text;
  v_land_type text;
  v_price numeric;
  v_area numeric;
begin
  if v_user_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  if p_property is null or jsonb_typeof(p_property) <> 'object' then
    raise exception 'Invalid property payload' using errcode = '22023';
  end if;

  if p_phone is null or length(btrim(p_phone)) < 5 or length(btrim(p_phone)) > 30 then
    raise exception 'A valid phone number is required' using errcode = '22023';
  end if;

  if nullif(btrim(p_property->>'title'), '') is null
     or nullif(btrim(p_property->>'governorate'), '') is null
     or nullif(btrim(p_property->>'city'), '') is null then
    raise exception 'Title, governorate, and city are required' using errcode = '22023';
  end if;

  v_property_type := nullif(btrim(p_property->>'property_type'), '');
  if v_property_type is null or v_property_type not in ('land', 'agricultural_land', 'house', 'apartment', 'commercial') then
    raise exception 'Invalid property type' using errcode = '22023';
  end if;

  v_advertiser_type := nullif(btrim(p_property->>'advertiser_type'), '');
  if v_advertiser_type is null or v_advertiser_type not in ('owner', 'broker', 'agency') then
    raise exception 'Invalid advertiser type' using errcode = '22023';
  end if;

  begin
    v_price := nullif(btrim(p_property->>'price'), '')::numeric;
    v_area := nullif(btrim(p_property->>'area'), '')::numeric;
  exception
    when invalid_text_representation or numeric_value_out_of_range then
      raise exception 'Price and area must be valid numbers' using errcode = '22023';
  end;

  if v_price is null or v_area is null
     or v_price <= 0 or v_area <= 0
     or v_price::text in ('NaN', 'Infinity', '-Infinity')
     or v_area::text in ('NaN', 'Infinity', '-Infinity') then
    raise exception 'Price and area must be greater than zero' using errcode = '22023';
  end if;

  v_ownership_type := nullif(btrim(p_property->>'ownership_type'), '');
  v_land_type := nullif(btrim(p_property->>'land_type'), '');

  if v_property_type in ('land', 'agricultural_land') then
    if v_ownership_type is null or v_ownership_type not in ('individual', 'shared')
       or v_land_type is null or v_land_type not in ('residential', 'agricultural') then
      raise exception 'Land listings require valid ownership and land classification' using errcode = '22023';
    end if;
  elsif v_ownership_type is not null or v_land_type is not null then
    raise exception 'Ownership and land classification apply only to land listings' using errcode = '22023';
  end if;

  insert into public.properties (
    owner_id, title, description, property_type, governorate, city,
    price, area, ownership_type, land_type, advertiser_type, image_urls, status
  ) values (
    v_user_id,
    btrim(p_property->>'title'),
    nullif(btrim(p_property->>'description'), ''),
    v_property_type,
    btrim(p_property->>'governorate'),
    btrim(p_property->>'city'),
    v_price,
    v_area,
    v_ownership_type,
    v_land_type,
    v_advertiser_type,
    '[]'::jsonb,
    'pending'
  )
  returning id into v_property_id;

  insert into private.property_contacts(property_id, owner_id, phone)
  values (v_property_id, v_user_id, btrim(p_phone));

  return v_property_id;
end;
$function$;

-- SECURITY DEFINER RPC: only signed-in users may submit a listing.
revoke all on function public.create_property_with_contact(jsonb, text)
  from public, anon, service_role;
grant execute on function public.create_property_with_contact(jsonb, text)
  to authenticated;

-- The browser cleanup path may delete only the caller's own pending listing;
-- the existing row-level DELETE policy enforces that ownership/status boundary.
grant delete on table public.properties to authenticated;
