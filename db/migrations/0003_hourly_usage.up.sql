-- phase 7.37: the per-organization analysis limit is per hour (contract §5.3,
-- owner decision november 9, 2026). upload_usage keeps one row per day, which
-- cannot express an hour, so jobs are also counted per minute here and the
-- limit sums the last 60 minutes: a rolling window, so bursting across a
-- clock-hour boundary cannot double it. rows older than a day are trimmed by
-- the server on each charge.
begin;

create table if not exists upload_usage_minutes (
    organization_id  TEXT not null references organizations (id) on delete cascade,
    minute           TIMESTAMPTZ not null,
    analyses_count   INT not null default 0 check (analyses_count >= 0),
    primary key (organization_id, minute)
);

commit;
