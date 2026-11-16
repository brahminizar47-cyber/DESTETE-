alter table public.properties
  add column if not exists price_type text not null default 'total',
  add column if not exists area_unit text not null default 'sqm',
  add column if not exists latitude double precision,
  add column if not exists longitude double precision,
  add column if not exists updated_at timestamptz not null default now();

alter table public.properties
  add constraint properties_price_type_check check (price_type in ('total', 'per_sqm', 'per_hectare')),
  add constraint properties_area_unit_check check (area_unit in ('sqm', 'hectare')),
  add constraint properties_coordinates_pair_check check ((latitude is null and longitude is null) or (latitude between -90 and 90 and longitude between -180 and 180));

alter table public.properties
  add column total_price numeric generated always as (
    case
      when price_type = 'total' then price
      when price_type = 'per_sqm' then price * area * case when area_unit = 'hectare' then 10000::numeric else 1::numeric end
      when price_type = 'per_hectare' then price * area * case when area_unit = 'hectare' then 1::numeric else 0.0001::numeric end
    end
  ) stored;

create index if not exists properties_total_price_idx on public.properties (total_price) where status = 'published';
create index if not exists properties_coordinates_idx on public.properties (latitude, longitude) where status = 'published' and latitude is not null and longitude is not null;

create or replace function private.set_property_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at := pg_catalog.now(); return new; end;
$$;
drop trigger if exists properties_set_updated_at on public.properties;
create trigger properties_set_updated_at before update on public.properties for each row execute function private.set_property_updated_at();

create table if not exists public.saved_searches (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  label text not null default '',
  filters jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint saved_searches_filters_object check (jsonb_typeof(filters) = 'object'),
  constraint saved_searches_label_length check (char_length(label) <= 80)
);
create index if not exists saved_searches_user_created_idx on public.saved_searches (user_id, created_at desc);
alter table public.saved_searches enable row level security;
revoke all on public.saved_searches from public, anon;
grant select, insert, update, delete on public.saved_searches to authenticated;
drop policy if exists "Users read their own saved searches" on public.saved_searches;
create policy "Users read their own saved searches" on public.saved_searches for select to authenticated using ((select auth.uid()) = user_id);
drop policy if exists "Users create their own saved searches" on public.saved_searches;
create policy "Users create their own saved searches" on public.saved_searches for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users update their own saved searches" on public.saved_searches;
create policy "Users update their own saved searches" on public.saved_searches for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
drop policy if exists "Users delete their own saved searches" on public.saved_searches;
create policy "Users delete their own saved searches" on public.saved_searches for delete to authenticated using ((select auth.uid()) = user_id);

create or replace function public.create_property_with_contact(p_property jsonb, p_phone text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_user_id uuid := auth.uid(); v_property_id uuid; v_property_type text; v_advertiser_type text;
  v_ownership_type text; v_land_type text; v_price_type text; v_area_unit text;
  v_price numeric; v_area numeric; v_latitude double precision; v_longitude double precision;
begin
  if v_user_id is null then raise exception 'Authentication required' using errcode = '28000'; end if;
  if p_property is null or jsonb_typeof(p_property) <> 'object' then raise exception 'Invalid property payload' using errcode = '22023'; end if;
  if p_phone is null or length(btrim(p_phone)) < 5 or length(btrim(p_phone)) > 30 then raise exception 'A valid phone number is required' using errcode = '22023'; end if;
  if nullif(btrim(p_property->>'title'), '') is null or nullif(btrim(p_property->>'governorate'), '') is null or nullif(btrim(p_property->>'city'), '') is null then raise exception 'Title, governorate, and city are required' using errcode = '22023'; end if;
  v_property_type := nullif(btrim(p_property->>'property_type'), '');
  if v_property_type is null or v_property_type not in ('land', 'agricultural_land', 'house', 'apartment', 'commercial') then raise exception 'Invalid property type' using errcode = '22023'; end if;
  v_advertiser_type := nullif(btrim(p_property->>'advertiser_type'), '');
  if v_advertiser_type is null or v_advertiser_type not in ('owner', 'broker', 'agency') then raise exception 'Invalid advertiser type' using errcode = '22023'; end if;
  v_price_type := coalesce(nullif(btrim(p_property->>'price_type'), ''), 'total');
  v_area_unit := coalesce(nullif(btrim(p_property->>'area_unit'), ''), 'sqm');
  if v_price_type not in ('total', 'per_sqm', 'per_hectare') then raise exception 'Invalid price type' using errcode = '22023'; end if;
  if v_area_unit not in ('sqm', 'hectare') then raise exception 'Invalid area unit' using errcode = '22023'; end if;
  begin
    v_price := nullif(btrim(p_property->>'price'), '')::numeric;
    v_area := nullif(btrim(p_property->>'area'), '')::numeric;
    v_latitude := nullif(btrim(p_property->>'latitude'), '')::double precision;
    v_longitude := nullif(btrim(p_property->>'longitude'), '')::double precision;
  exception when invalid_text_representation or numeric_value_out_of_range then
    raise exception 'Price, area, and coordinates must be valid numbers' using errcode = '22023';
  end;
  if v_price is null or v_area is null or v_price <= 0 or v_area <= 0 or v_price::text in ('NaN', 'Infinity', '-Infinity') or v_area::text in ('NaN', 'Infinity', '-Infinity') then
    raise exception 'Price and area must be greater than zero' using errcode = '22023';
  end if;
  if (v_latitude is null) <> (v_longitude is null) or (v_latitude is not null and (v_latitude < -90 or v_latitude > 90 or v_longitude < -180 or v_longitude > 180)) then
    raise exception 'Latitude and longitude must both be valid or both be empty' using errcode = '22023';
  end if;
  v_ownership_type := nullif(btrim(p_property->>'ownership_type'), '');
  v_land_type := nullif(btrim(p_property->>'land_type'), '');
  if v_property_type in ('land', 'agricultural_land') then
    if v_ownership_type is null or v_ownership_type not in ('individual', 'shared') or v_land_type is null or v_land_type not in ('residential', 'agricultural') then
      raise exception 'Land listings require valid ownership and land classification' using errcode = '22023';
    end if;
  elsif v_ownership_type is not null or v_land_type is not null then
    raise exception 'Ownership and land classification apply only to land listings' using errcode = '22023';
  end if;
  insert into public.properties (owner_id,title,description,property_type,governorate,city,price,price_type,area,area_unit,latitude,longitude,ownership_type,land_type,advertiser_type,image_urls,status)
  values (v_user_id,btrim(p_property->>'title'),nullif(btrim(p_property->>'description'),''),v_property_type,btrim(p_property->>'governorate'),btrim(p_property->>'city'),v_price,v_price_type,v_area,v_area_unit,v_latitude,v_longitude,v_ownership_type,v_land_type,v_advertiser_type,'[]'::jsonb,'pending')
  returning id into v_property_id;
  insert into private.property_contacts(property_id,owner_id,phone) values (v_property_id,v_user_id,btrim(p_phone));
  return v_property_id;
end;
$$;

create or replace function public.notify_favorited_property_changes()
returns trigger language plpgsql security definer set search_path = '' as $$
declare v_title text; v_body text;
begin
  if new.price is distinct from old.price or new.price_type is distinct from old.price_type or new.area_unit is distinct from old.area_unit then
    v_title := 'تحديث سعر عقار محفوظ'; v_body := 'تم تحديث طريقة عرض السعر أو قيمته في عقار أضفته إلى المفضّلة.';
  elsif new.ownership_type is distinct from old.ownership_type then
    v_title := 'تحديث نوع ملكية عقار محفوظ'; v_body := 'تم تحديث نوع ملكية عقار أضفته إلى المفضّلة.';
  elsif new.availability_status is distinct from old.availability_status or new.status is distinct from old.status then
    v_title := 'تحديث حالة عقار محفوظ'; v_body := 'تم تحديث حالة عقار أضفته إلى المفضّلة.';
  elsif new.image_urls is distinct from old.image_urls then
    v_title := 'تحديث صور عقار محفوظ'; v_body := 'تم تحديث صور عقار أضفته إلى المفضّلة.';
  else return new;
  end if;
  insert into public.user_notifications(recipient_id,notification_type,title,body,property_id)
  select f.user_id,'favorite_listing_update',v_title,v_body,new.id from public.property_favorites f where f.property_id=new.id and f.user_id<>new.owner_id;
  insert into private.favorite_listing_email_queue(recipient_id,property_id,property_title,notification_title,notification_body)
  select f.user_id,new.id,new.title,v_title,v_body from public.property_favorites f where f.property_id=new.id and f.user_id<>new.owner_id;
  return new;
end;
$$;
drop trigger if exists favorited_property_update_notification on public.properties;
create trigger favorited_property_update_notification after update of price,price_type,area_unit,ownership_type,availability_status,status,image_urls on public.properties for each row execute function public.notify_favorited_property_changes();
