-- Add indexes for foreign-key columns used by messaging, reviews, and notifications.
-- These indexes are safe to apply repeatedly and do not change existing data.

create index if not exists property_messages_sender_id_idx
  on public.property_messages (sender_id);

create index if not exists property_reviews_reviewer_id_idx
  on public.property_reviews (reviewer_id);

create index if not exists user_notifications_conversation_id_idx
  on public.user_notifications (conversation_id);

create index if not exists user_notifications_property_id_idx
  on public.user_notifications (property_id);
