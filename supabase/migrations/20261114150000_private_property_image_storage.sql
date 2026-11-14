-- Make property images private and serve them only through short-lived signed URLs.
-- Convert existing public URLs to storage object paths before disabling public access.

update public.properties p
set image_urls = (
  select coalesce(
    jsonb_agg(
      to_jsonb(
        case
          when image_url like 'https://zmipxldmmfkfpsldvium.supabase.co/storage/v1/object/public/property-images/%'
            then substring(image_url from length('https://zmipxldmmfkfpsldvium.supabase.co/storage/v1/object/public/property-images/') + 1)
          else image_url
        end
      )
    ),
    '[]'::jsonb
  )
  from jsonb_array_elements_text(p.image_urls) as images(image_url)
)
where jsonb_typeof(p.image_urls) = 'array'
  and exists (
    select 1
    from jsonb_array_elements_text(p.image_urls) as images(image_url)
    where image_url like 'https://zmipxldmmfkfpsldvium.supabase.co/storage/v1/object/public/property-images/%'
  );

create or replace function public.finalize_property_images(p_property_id uuid, p_image_urls jsonb)
returns boolean
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_uid uuid := auth.uid();
  v_item jsonb;
  v_path text;
  v_filename text;
  v_prefix text;
  v_count integer;
  v_found boolean;
begin
  if v_uid is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  if p_property_id is null then
    raise exception 'Property ID is required' using errcode = '22023';
  end if;

  if p_image_urls is null or jsonb_typeof(p_image_urls) <> 'array' then
    raise exception 'Images must be supplied as an array' using errcode = '22023';
  end if;

  v_count := jsonb_array_length(p_image_urls);
  if v_count < 1 or v_count > 8 then
    raise exception 'A listing must contain between 1 and 8 images' using errcode = '22023';
  end if;

  v_prefix := v_uid::text || '/' || p_property_id::text || '/';

  for v_item in
    select value from jsonb_array_elements(p_image_urls)
  loop
    if jsonb_typeof(v_item) <> 'string' then
      raise exception 'Every image path must be a string' using errcode = '22023';
    end if;

    v_path := v_item #>> '{}';
    if v_path is null or left(v_path, length(v_prefix)) <> v_prefix then
      raise exception 'An image path does not belong to this listing' using errcode = '22023';
    end if;

    v_filename := substring(v_path from length(v_prefix) + 1);
    if v_filename = ''
       or position('/' in v_filename) > 0
       or v_filename !~ '^[A-Za-z0-9._-]+[.](jpg|png|webp)$' then
      raise exception 'Invalid property image path' using errcode = '22023';
    end if;

    select exists (
      select 1
      from storage.objects o
      where o.bucket_id = 'property-images'
        and o.name = v_path
        and o.owner_id = v_uid::text
        and lower(coalesce(o.metadata->>'mimetype', '')) in ('image/jpeg', 'image/png', 'image/webp')
        and coalesce(
          case
            when (o.metadata->>'size') ~ '^[0-9]+$'
              then (o.metadata->>'size')::bigint
            else null
          end,
          0
        ) between 1 and 5242880
    ) into v_found;

    if not v_found then
      raise exception 'An uploaded image is missing, oversized, or has an unsupported type' using errcode = '22023';
    end if;
  end loop;

  update public.properties
     set image_urls = p_image_urls
   where id = p_property_id
     and owner_id = v_uid
     and status = 'pending';

  if not found then
    raise exception 'Pending listing not found or not owned by the current user' using errcode = 'P0002';
  end if;

  return true;
end;
$function$;

drop policy if exists "Read published property images through signed URLs" on storage.objects;
create policy "Read published property images through signed URLs"
on storage.objects
for select
to anon, authenticated
using (
  bucket_id = 'property-images'
  and (
    (
      auth.uid() is not null
      and (storage.foldername(name))[1] = auth.uid()::text
    )
    or exists (
      select 1
      from public.properties p
      where p.id::text = (storage.foldername(name))[2]
        and p.status = 'published'
        and p.expires_at > now()
        and exists (
          select 1
          from jsonb_array_elements_text(p.image_urls) as image_path(path)
          where image_path.path = storage.objects.name
        )
    )
    or (auth.uid() is not null and public.is_admin())
  )
);

update storage.buckets
set public = false
where id = 'property-images';

