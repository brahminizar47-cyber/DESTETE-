alter table public.properties drop constraint if exists properties_coordinates_pair_check;
alter table public.properties add constraint properties_coordinates_pair_check check (((latitude is null) = (longitude is null)) and (latitude is null or (latitude between -90 and 90 and longitude between -180 and 180)));
