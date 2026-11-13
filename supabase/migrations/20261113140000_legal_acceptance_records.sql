create table if not exists private.legal_acceptances (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  terms_version text not null,
  privacy_version text not null,
  accepted_at timestamptz not null default now(),
  source text not null default 'signup'
    check (source in ('signup', 'existing_user_reacceptance')),
  constraint legal_acceptances_user_versions_unique
    unique (user_id, terms_version, privacy_version)
);

alter table private.legal_acceptances enable row level security;
revoke all on table private.legal_acceptances from public, anon, authenticated;

create or replace function public.record_legal_acceptance(
  p_terms_version text,
  p_privacy_version text
)
returns void
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_user_id uuid := auth.uid();
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if p_terms_version is distinct from '2026-11-13-v1'
     or p_privacy_version is distinct from '2026-11-13-v1' then
    raise exception 'Unsupported legal document version';
  end if;

  insert into private.legal_acceptances (
    user_id, terms_version, privacy_version, source
  )
  values (
    v_user_id, p_terms_version, p_privacy_version, 'existing_user_reacceptance'
  )
  on conflict (user_id, terms_version, privacy_version) do nothing;
end;
$function$;

revoke all on function public.record_legal_acceptance(text, text) from public, anon;
grant execute on function public.record_legal_acceptance(text, text) to authenticated;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path to ''
as $function$
begin
  insert into public.profiles (
    id,
    full_name,
    phone,
    governorate
  )
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    new.raw_user_meta_data ->> 'phone',
    new.raw_user_meta_data ->> 'governorate'
  );

  if new.raw_user_meta_data ->> 'accepted_terms_version' = '2026-11-13-v1'
     and new.raw_user_meta_data ->> 'accepted_privacy_version' = '2026-11-13-v1' then
    insert into private.legal_acceptances (
      user_id, terms_version, privacy_version, source
    )
    values (
      new.id, '2026-11-13-v1', '2026-11-13-v1', 'signup'
    )
    on conflict (user_id, terms_version, privacy_version) do nothing;
  end if;

  return new;
end;
$function$;