-- DESTATE account hub: private buyer/seller conversations and per-user notifications
create table if not exists public.property_conversations (
  id uuid primary key default gen_random_uuid(),
  property_id uuid not null references public.properties(id) on delete cascade,
  buyer_id uuid not null references auth.users(id) on delete cascade,
  seller_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  last_message_at timestamptz not null default now(),
  constraint property_conversations_distinct_users check (buyer_id <> seller_id),
  constraint property_conversations_unique_buyer_property unique (property_id, buyer_id)
);

create table if not exists public.property_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.property_conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (char_length(btrim(body)) between 1 and 3000),
  created_at timestamptz not null default now(),
  read_at timestamptz
);

create table if not exists public.user_notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null references auth.users(id) on delete cascade,
  notification_type text not null,
  title text not null,
  body text not null default '',
  property_id uuid references public.properties(id) on delete set null,
  conversation_id uuid references public.property_conversations(id) on delete cascade,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists property_conversations_buyer_recent_idx on public.property_conversations(buyer_id,last_message_at desc);
create index if not exists property_conversations_seller_recent_idx on public.property_conversations(seller_id,last_message_at desc);
create index if not exists property_messages_conversation_recent_idx on public.property_messages(conversation_id,created_at);
create index if not exists property_messages_unread_idx on public.property_messages(conversation_id,read_at) where read_at is null;
create index if not exists user_notifications_recipient_recent_idx on public.user_notifications(recipient_id,created_at desc);
create index if not exists user_notifications_unread_idx on public.user_notifications(recipient_id,is_read) where is_read=false;

alter table public.property_conversations enable row level security;
alter table public.property_messages enable row level security;
alter table public.user_notifications enable row level security;

revoke all on public.property_conversations, public.property_messages, public.user_notifications from anon, authenticated;
grant select on public.property_conversations, public.property_messages, public.user_notifications to authenticated;
grant update (read_at) on public.property_messages to authenticated;
grant update (is_read) on public.user_notifications to authenticated;

drop policy if exists "Participants read conversations" on public.property_conversations;
create policy "Participants read conversations" on public.property_conversations
for select to authenticated using ((select auth.uid()) in (buyer_id,seller_id));

drop policy if exists "Participants read conversation messages" on public.property_messages;
create policy "Participants read conversation messages" on public.property_messages
for select to authenticated using (exists (
  select 1 from public.property_conversations c
  where c.id=conversation_id and (select auth.uid()) in (c.buyer_id,c.seller_id)
));

drop policy if exists "Recipients mark incoming messages read" on public.property_messages;
create policy "Recipients mark incoming messages read" on public.property_messages
for update to authenticated
using (sender_id <> (select auth.uid()) and exists (
  select 1 from public.property_conversations c
  where c.id=conversation_id and (select auth.uid()) in (c.buyer_id,c.seller_id)
))
with check (sender_id <> (select auth.uid()) and exists (
  select 1 from public.property_conversations c
  where c.id=conversation_id and (select auth.uid()) in (c.buyer_id,c.seller_id)
));

drop policy if exists "Users read their own notifications" on public.user_notifications;
create policy "Users read their own notifications" on public.user_notifications
for select to authenticated using (recipient_id=(select auth.uid()));

drop policy if exists "Users mark their own notifications read" on public.user_notifications;
create policy "Users mark their own notifications read" on public.user_notifications
for update to authenticated using (recipient_id=(select auth.uid()))
with check (recipient_id=(select auth.uid()));

create or replace function public.start_property_conversation(p_property_id uuid,p_first_message text)
returns uuid language plpgsql security definer set search_path=''
as $$
declare v_user uuid := auth.uid(); v_seller uuid; v_status text; v_conversation uuid;
begin
  if v_user is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_first_message is null or char_length(btrim(p_first_message)) not between 1 and 3000 then raise exception 'INVALID_MESSAGE'; end if;
  select p.owner_id,p.status into v_seller,v_status from public.properties p where p.id=p_property_id;
  if not found or v_status <> 'published' then raise exception 'LISTING_UNAVAILABLE'; end if;
  if v_seller=v_user then raise exception 'CANNOT_MESSAGE_SELF'; end if;
  insert into public.property_conversations(property_id,buyer_id,seller_id)
  values(p_property_id,v_user,v_seller)
  on conflict(property_id,buyer_id) do update set last_message_at=now()
  returning id into v_conversation;
  insert into public.property_messages(conversation_id,sender_id,body)
  values(v_conversation,v_user,btrim(p_first_message));
  return v_conversation;
end;
$$;

create or replace function public.send_property_message(p_conversation_id uuid,p_body text)
returns uuid language plpgsql security definer set search_path=''
as $$
declare v_user uuid := auth.uid(); v_message uuid;
begin
  if v_user is null then raise exception 'AUTH_REQUIRED'; end if;
  if p_body is null or char_length(btrim(p_body)) not between 1 and 3000 then raise exception 'INVALID_MESSAGE'; end if;
  if not exists (select 1 from public.property_conversations c where c.id=p_conversation_id and v_user in (c.buyer_id,c.seller_id)) then raise exception 'NOT_CONVERSATION_PARTICIPANT'; end if;
  insert into public.property_messages(conversation_id,sender_id,body)
  values(p_conversation_id,v_user,btrim(p_body)) returning id into v_message;
  return v_message;
end;
$$;

revoke all on function public.start_property_conversation(uuid,text) from public,anon;
revoke all on function public.send_property_message(uuid,text) from public,anon;
grant execute on function public.start_property_conversation(uuid,text) to authenticated;
grant execute on function public.send_property_message(uuid,text) to authenticated;

create or replace function public.handle_property_message_insert()
returns trigger language plpgsql security definer set search_path=''
as $$
declare v_conversation public.property_conversations%rowtype; v_recipient uuid;
begin
  select * into v_conversation from public.property_conversations where id=new.conversation_id;
  if not found or new.sender_id not in (v_conversation.buyer_id,v_conversation.seller_id) then raise exception 'INVALID_CONVERSATION_SENDER'; end if;
  update public.property_conversations set last_message_at=new.created_at where id=new.conversation_id;
  v_recipient := case when new.sender_id=v_conversation.buyer_id then v_conversation.seller_id else v_conversation.buyer_id end;
  insert into public.user_notifications(recipient_id,notification_type,title,body,property_id,conversation_id)
  values(v_recipient,'new_message','رسالة جديدة','وصلتك رسالة جديدة بخصوص إعلان أو عقار تتابعه.',v_conversation.property_id,v_conversation.id);
  return new;
end;
$$;
drop trigger if exists property_message_notification on public.property_messages;
create trigger property_message_notification after insert on public.property_messages
for each row execute function public.handle_property_message_insert();

create or replace function public.notify_favorited_property_changes()
returns trigger language plpgsql security definer set search_path=''
as $$
declare v_title text; v_body text;
begin
  if new.price is distinct from old.price then
    v_title := 'تغيير سعر عقار محفوظ'; v_body := 'تغيّر سعر عقار أضفته إلى المفضّلة.';
  elsif new.ownership_type is distinct from old.ownership_type then
    v_title := 'تحديث نوع ملكية عقار محفوظ'; v_body := 'تم تحديث نوع ملكية عقار أضفته إلى المفضّلة.';
  elsif new.availability_status is distinct from old.availability_status or new.status is distinct from old.status then
    v_title := 'تحديث حالة عقار محفوظ'; v_body := 'تم تحديث حالة عقار أضفته إلى المفضّلة.';
  elsif new.image_urls is distinct from old.image_urls then
    v_title := 'تحديث صور عقار محفوظ'; v_body := 'تم تحديث صور عقار أضفته إلى المفضّلة.';
  else return new;
  end if;
  insert into public.user_notifications(recipient_id,notification_type,title,body,property_id)
  select f.user_id,'favorite_listing_update',v_title,v_body,new.id
  from public.property_favorites f where f.property_id=new.id and f.user_id<>new.owner_id;
  return new;
end;
$$;
drop trigger if exists favorited_property_update_notification on public.properties;
create trigger favorited_property_update_notification after update of price,ownership_type,availability_status,status,image_urls on public.properties
for each row execute function public.notify_favorited_property_changes();

revoke all on function public.handle_property_message_insert() from public,anon,authenticated;
revoke all on function public.notify_favorited_property_changes() from public,anon,authenticated;
