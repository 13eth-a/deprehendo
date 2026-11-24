-- replace the constraint only; stored object keys continue to address the original bytes.
alter table uploads drop constraint uploads_object_key_check;
alter table uploads add constraint uploads_object_key_check
    check (object_key ~ '^orgs/[a-z0-9_-]+/bundles/[0-9a-f]{64}\.(deprehendo|runopsy)$');
