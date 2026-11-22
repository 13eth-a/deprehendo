-- reverse of 0004_confidence_band.up.sql.
begin;

alter table incidents drop column if exists confidence_band;

commit;
