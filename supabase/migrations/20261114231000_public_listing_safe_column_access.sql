-- Preserve public browsing of published listings without exposing private columns.
-- RLS still limits anon rows to status='published'. Column-level grants intentionally
-- exclude owner_id and phone; contact details remain behind the contact workflow.
grant select (
  id,
  title,
  description,
  property_type,
  governorate,
  city,
  price,
  area,
  advertiser_type,
  ownership_type,
  land_type,
  image_urls,
  created_at,
  expires_at,
  availability_status,
  status
) on table public.properties to anon, authenticated;
