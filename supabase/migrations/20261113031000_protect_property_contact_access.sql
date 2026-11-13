-- Protect advertiser phone numbers at the database privilege layer.
-- Apply this migration only AFTER the application version that reads phone numbers
-- through public.get_property_contact() has been deployed.

-- Remove broad table-level reads, then explicitly allow every public listing field
-- except the legacy properties.phone column.
revoke select on table public.properties from anon, authenticated;
revoke select (phone) on table public.properties from anon, authenticated;

grant select (
  id,
  owner_id,
  title,
  description,
  property_type,
  governorate,
  city,
  address,
  price,
  area,
  bedrooms,
  status,
  created_at,
  availability_status,
  image_urls,
  advertiser_type,
  ownership_type,
  land_type
) on table public.properties to anon, authenticated;

-- New listings must be created through the validated SECURITY DEFINER RPC,
-- which also stores the phone in private.property_contacts.
revoke insert on table public.properties from authenticated;
revoke insert (
  owner_id,
  title,
  description,
  property_type,
  governorate,
  city,
  price,
  area,
  image_urls,
  advertiser_type,
  ownership_type,
  land_type,
  status,
  phone
) on table public.properties from authenticated;
