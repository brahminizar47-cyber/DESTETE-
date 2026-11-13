-- DESTATE security hardening and query-plan improvements.
-- Safe, additive changes only. Existing data is preserved.

-- These functions are invoked by database triggers, not by browser/API clients.
revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.rls_auto_enable() from public, anon, authenticated;

-- Admin status is needed only by signed-in users. The function returns no admin
-- identity data and is used by the authenticated admin interface and policies.
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- Keep the public reviews RPC available intentionally: it returns only public
-- rating/comment data and never exposes reviewer IDs or contact information.
revoke all on function public.get_advertiser_reviews(uuid) from public;
grant execute on function public.get_advertiser_reviews(uuid) to anon, authenticated;

-- Index foreign-key columns used for joins, deletes, and owner-scoped access.
create index if not exists properties_owner_id_idx
  on public.properties(owner_id);
create index if not exists property_images_owner_id_idx
  on public.property_images(owner_id);
create index if not exists property_images_property_id_idx
  on public.property_images(property_id);
create index if not exists advertiser_reviews_reviewer_id_idx
  on public.advertiser_reviews(reviewer_id);
create index if not exists platform_reports_property_id_idx
  on public.platform_reports(property_id);
create index if not exists property_contact_events_advertiser_id_idx
  on public.property_contact_events(advertiser_id);
create index if not exists property_contact_events_property_id_idx
  on public.property_contact_events(property_id);

-- Avoid per-row auth.uid() evaluation in frequently used RLS predicates.
drop policy if exists "Owners can view their own properties" on public.properties;
create policy "Owners can view their own properties"
  on public.properties for select to authenticated
  using ((select auth.uid()) = owner_id);

drop policy if exists "Owners can submit pending properties" on public.properties;
create policy "Owners can submit pending properties"
  on public.properties for insert to authenticated
  with check ((select auth.uid()) = owner_id and status = 'pending');

drop policy if exists "Owners can delete their pending properties" on public.properties;
create policy "Owners can delete their pending properties"
  on public.properties for delete to authenticated
  using ((select auth.uid()) = owner_id and status = 'pending');

drop policy if exists "Admins can delete all properties" on public.properties;
create policy "Admins can delete all properties"
  on public.properties for delete to authenticated
  using ((select public.is_admin()));

drop policy if exists "Admins can update all properties" on public.properties;
create policy "Admins can update all properties"
  on public.properties for update to authenticated
  using ((select public.is_admin()))
  with check ((select public.is_admin()));

drop policy if exists "Admins can view all properties" on public.properties;
create policy "Admins can view all properties"
  on public.properties for select to authenticated
  using ((select public.is_admin()));

drop policy if exists "Owners view their own images" on public.property_images;
create policy "Owners view their own images"
  on public.property_images for select to authenticated
  using ((select auth.uid()) = owner_id);

drop policy if exists "Owners add images to their pending properties" on public.property_images;
create policy "Owners add images to their pending properties"
  on public.property_images for insert to authenticated
  with check (
    (select auth.uid()) = owner_id
    and exists (
      select 1 from public.properties p
      where p.id = property_images.property_id
        and p.owner_id = (select auth.uid())
        and p.status = 'pending'
    )
  );

drop policy if exists "Owners delete their pending images" on public.property_images;
create policy "Owners delete their pending images"
  on public.property_images for delete to authenticated
  using (
    (select auth.uid()) = owner_id
    and exists (
      select 1 from public.properties p
      where p.id = property_images.property_id
        and p.owner_id = (select auth.uid())
        and p.status = 'pending'
    )
  );

drop policy if exists "Owners view their own profile" on public.profiles;
create policy "Owners view their own profile"
  on public.profiles for select to authenticated
  using ((select auth.uid()) = id);

drop policy if exists "Owners create their own profile" on public.profiles;
create policy "Owners create their own profile"
  on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);

drop policy if exists "Owners update their own profile" on public.profiles;
create policy "Owners update their own profile"
  on public.profiles for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- The legacy admins table is retained for compatibility, but its old policy
-- queried the same table recursively. Restrict it to a user's own row.
drop policy if exists "Admins can view admin list" on public.admins;
create policy "Admins can view own legacy admin row"
  on public.admins for select to authenticated
  using (user_id = (select auth.uid()));
