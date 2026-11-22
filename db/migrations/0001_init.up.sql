-- phase 7: organizations, memberships, uploads, analyses (docs/cloud/contract.md
-- §7.1). metadata only: bundle bytes live in object storage, keyed per §6
-- (orgs/{organization_id}/bundles/{sha256}.runopsy). the web app owns auth
-- tables beyond these two; tokens are hashed here (7.12) so a database dump
-- never yields a usable credential.
--
-- every query that reads incident data joins through organization_id; there
-- is deliberately no incidents-by-id path (§2.3).

begin;

create table organizations (
    id          TEXT primary key,             -- org_ + lowercase hex (clouddb.NewID)
    name        TEXT not null check (length(name) between 1 and 200),
    created_at  TIMESTAMPTZ not null default now()
);

create table memberships (
    user_id          TEXT not null,           -- library-auth user id
    organization_id  TEXT not null references organizations (id) on delete cascade,
    role             TEXT not null check (role in ('owner', 'member')),
    created_at       TIMESTAMPTZ not null default now(),
    primary key (user_id, organization_id)
);
create index memberships_by_user on memberships (user_id);

create table personal_tokens (
    id              TEXT primary key,
    user_id         TEXT not null,
    organization_id TEXT not null references organizations (id) on delete cascade,
    description     TEXT not null default '',
    -- SHA-256 of the raw token; the raw token is never stored or logged.
    token_hash      BYTEA not null check (length(token_hash) = 32),
    created_at      TIMESTAMPTZ not null default now(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    unique (user_id, token_hash)
);
-- authentication looks a token up by its hash alone, before it knows the user;
-- the composite UNIQUE above cannot serve that query.
create index personal_tokens_by_hash on personal_tokens (token_hash) where revoked_at is null;

create table uploads (
    id               TEXT primary key,        -- upl_…
    organization_id  TEXT not null references organizations (id) on delete cascade,
    sha256           BYTEA not null check (length(sha256) = 32),
    -- key shape is enforced here, not only in the application (§6): a key
    -- with a path escape, uppercase hex or another suffix is not storable.
    object_key       TEXT not null check (object_key ~ '^orgs/[a-z0-9_-]+/bundles/[0-9a-f]{64}\.runopsy$'),
    size_bytes       BIGINT not null check (size_bytes >= 22),
    incident_id      TEXT not null,           -- display/search field, not a key (§2.3)
    schema_version   INT  not null,
    format_version   INT  not null,
    uploaded_by      TEXT not null,
    uploaded_at      TIMESTAMPTZ not null default now(),
    -- duplicate = same organization, same bytes (§6): complete returns the
    -- existing incident instead of a second upload.
    unique (organization_id, sha256)
);
create index uploads_by_incident on uploads (organization_id, incident_id, uploaded_at desc);
-- no second (organization_id, incident_id) index: uploads_by_incident serves
-- that prefix already, and the extra index only costs writes (7.56 review, P3).

create table analyses (
    id            TEXT primary key,           -- ana_…
    upload_id     TEXT not null references uploads (id) on delete cascade,
    engine        JSONB not null,             -- analysis.Engine document (§4)
    engine_key    TEXT not null,              -- engine identity string; UNIQUE per upload
    status        TEXT not null check (status in ('PROCESSING', 'READY', 'UNSUPPORTED', 'REJECTED', 'FAILED_LIMIT', 'FAILED_CRASH')),
    error_class   TEXT,
    document_key  TEXT,                       -- storage key; set iff status = READY
    duration_ms   INT,
    created_at    TIMESTAMPTZ not null default now(),
    -- Append-only history (7.34): running the same engine twice is a no-op,
    -- original analyses are never edited or deleted while the upload exists.
    unique (upload_id, engine_key),
    -- A READY analysis without its document would 404 the first time a user
    -- opens it; a document under any other status is unreachable bytes
    -- (7.56 review, P2).
    constraint analyses_document_key_iff_ready
        check ((status = 'READY') = (document_key is not null))
);
create index analyses_by_status on analyses (upload_id, created_at desc);

-- view model for 7.6/7.25: searchable columns copied from the ACTIVE analysis
-- by the application, never from the bytes. Active/original split mirrors the
-- analyses table; switching active analysis is an explicit, audited action.
create table incidents (
    upload_id             TEXT primary key references uploads (id) on delete cascade,
    organization_id       TEXT not null references organizations (id) on delete cascade,
    external_incident_id  TEXT not null,
    active_analysis_id    TEXT references analyses (id) on delete set null,
    original_analysis_id  TEXT references analyses (id) on delete set null,
    triggered_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ not null default now(),
    primary_signature     TEXT,
    confidence            REAL,
    severity              TEXT,
    runner_name           TEXT,
    runner_version        TEXT,
    repository            TEXT,
    workflow              TEXT,
    job                   TEXT,
    run_id                TEXT,
    hostname_hash         TEXT,
    platform              TEXT,
    architecture          TEXT
);
create index incidents_by_created on incidents (organization_id, created_at desc);
create index incidents_by_signature on incidents (organization_id, primary_signature);
create index incidents_by_runner on incidents (organization_id, runner_name);
create index incidents_by_repository on incidents (organization_id, repository);

-- upload abuse counters (§5.3), updated by web on each complete; parse-seconds
-- accumulate per organization per day and are consulted before dispatch.
create table upload_usage (
    organization_id  TEXT not null references organizations (id) on delete cascade,
    day              DATE not null,
    analyses_count   INT not null default 0,
    parse_seconds    DOUBLE PRECISION not null default 0,
    primary key (organization_id, day)
);

commit;
