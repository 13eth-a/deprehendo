-- phase 7.58: index the time-based retention sweep reads. manual delete needs
-- no index; the sweep selects uploads by age alone, which has no supporting
-- prefix until this file.
begin;

create index if not exists uploads_by_uploaded_at on uploads (uploaded_at);

commit;
