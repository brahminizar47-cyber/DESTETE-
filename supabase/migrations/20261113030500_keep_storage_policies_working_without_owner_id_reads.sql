-- Keep property-image upload/delete checks working without granting users
-- direct SELECT access to properties.owner_id.
create or replace function public.can_manage_pending_property_images(p_property_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
  select exists (
    select 1
    from public.properties p
    where p.id = p_property_id
      and p.owner_id = auth.uid()
      and p.status = 'pending'
  );
$function$;

revoke all on function public.can_manage_pending_property_images(uuid)
  from public, anon, service_role;
grant execute on function public.can_manage_pending_property_images(uuid)
  to authenticated;

drop policy if exists "Owners upload property images" on storage.objects;
create policy "Owners upload property images"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'property-images'
  and (storage.foldername(name))[1] = auth.uid()::text
  and public.can_manage_pending_property_images(
    ((storage.foldername(name))[2])::uuid
  )
);

drop policy if exists "Owners delete property images" on storage.objects;
create policy "Owners delete property images"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'property-images'
  and (storage.foldername(name))[1] = auth.uid()::text
  and public.can_manage_pending_property_images(
    ((storage.foldername(name))[2])::uuid
  )
);
