-- reverse of 0002_retention_index.up.sql.

begin;

drop index if exists uploads_by_uploaded_at;

commit;
