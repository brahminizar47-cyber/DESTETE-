-- Remove legacy permissive policies that bypass the pending-listing ownership checks.
-- The narrower "Owners upload property images" and "Owners delete property images"
-- policies remain in place and require an owned pending listing in the expected path.

drop policy if exists "Users upload their own property images" on storage.objects;
drop policy if exists "Users delete their own property images" on storage.objects;
drop policy if exists "Users update their own property images" on storage.objects;
