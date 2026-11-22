-- reverse of 0001_init.up.sql. deletion is scoped to phase 7's own tables;
-- extensions and other tenants' objects are never touched.

begin;

drop table if exists upload_usage;
drop table if exists incidents;
drop table if exists analyses;
drop table if exists uploads;
drop table if exists personal_tokens;
drop table if exists memberships;
drop table if exists organizations;

commit;
