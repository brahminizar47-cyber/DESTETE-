-- Allow administrators to permanently delete listings and their Storage images.
-- Both policies are restricted to authenticated users for whom is_admin() returns true.

create policy "Admins can delete all properties"
on public.properties
for delete
to authenticated
using (public.is_admin());

create policy "Admins can delete property images"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'property-images'
  and public.is_admin()
);
