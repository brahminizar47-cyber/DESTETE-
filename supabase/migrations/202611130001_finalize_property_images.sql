-- Finalize uploaded listing photos only after the listing exists in pending state.
-- Apply this migration to Supabase before testing the revised publishing flow.

create or replace function public.finalize_property_images(
  p_property_id uuid,
  p_image_urls jsonb
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_uid uuid := auth.uid();
  v_url text;
  v_prefix text;
  v_count integer;
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;

  if p_property_id is null then
    raise exception 'Property ID is required';
  end if;

  if p_image_urls is null or jsonb_typeof(p_image_urls) <> 'array' then
    raise exception 'Images must be supplied as an array';
  end if;

  v_count := jsonb_array_length(p_image_urls);
  if v_count < 1 or v_count > 8 then
    raise exception 'A listing must contain between 1 and 8 images';
  end if;

  v_prefix := 'https://zmipxldmmfkfpsldvium.supabase.co/storage/v1/object/public/property-images/'
    || v_uid::text || '/' || p_property_id::text || '/';

  for v_url in
    select value
    from jsonb_array_elements_text(p_image_urls)
  loop
    if v_url is null or length(btrim(v_url)) = 0
       or left(v_url, length(v_prefix)) <> v_prefix then
      raise exception 'An image URL does not belong to this listing';
    end if;
  end loop;

  update public.properties
     set image_urls = p_image_urls
   where id = p_property_id
     and owner_id = v_uid
     and status = 'pending';

  if not found then
    raise exception 'Pending listing not found or not owned by the current user';
  end if;

  return true;
end;
$function$;

revoke all on function public.finalize_property_images(uuid, jsonb)
  from public, anon, service_role;
grant execute on function public.finalize_property_images(uuid, jsonb)
  to authenticated;
