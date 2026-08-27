-- Application data is private to FastAPI.  The runtime role's password is
-- provisioned out-of-band and is intentionally absent from this migration.

create schema private;

comment on schema private is
    'Application tables for the FastAPI control plane; never exposed through the Supabase Data API.';

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'app_runtime') then
        create role app_runtime
            login
            nosuperuser
            nocreatedb
            nocreaterole
            noinherit
            noreplication
            nobypassrls;
    else
        alter role app_runtime
            login
            nosuperuser
            nocreatedb
            nocreaterole
            noinherit
            noreplication
            nobypassrls;
    end if;
end;
$$;

comment on role app_runtime is
    'FastAPI runtime role. Set its password through deployment secret management, never in a migration.';

alter role app_runtime set search_path to private, pg_catalog;

revoke all on schema private from public;
revoke all on schema private from anon, authenticated;
revoke create on schema private from public;
revoke create on schema private from anon, authenticated;

create table private.app_users (
    id uuid primary key default gen_random_uuid(),
    supabase_user_id uuid not null,
    email_normalized text not null,
    device_epoch integer not null default 0,
    created_at timestamptz not null default current_timestamp,
    recovered_at timestamptz,
    deleted_at timestamptz,
    constraint app_users_supabase_user_id_key unique (supabase_user_id),
    constraint app_users_email_normalized_key unique (email_normalized),
    constraint app_users_email_normalized_length_check
        check (char_length(email_normalized) between 3 and 320),
    constraint app_users_device_epoch_check check (device_epoch >= 0),
    constraint app_users_recovered_at_check
        check (recovered_at is null or recovered_at >= created_at),
    constraint app_users_deleted_at_check
        check (deleted_at is null or deleted_at >= created_at),
    constraint app_users_supabase_user_fk
        foreign key (supabase_user_id)
        references auth.users (id)
        on delete cascade
);

create table private.devices (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    epoch integer not null,
    label text not null,
    signing_public_key_spki bytea not null,
    fingerprint bytea not null,
    status text not null default 'active',
    created_at timestamptz not null default current_timestamp,
    last_seen_at timestamptz not null default current_timestamp,
    revoked_at timestamptz,
    approved_by_device_id uuid,
    constraint devices_user_id_id_key unique (user_id, id),
    constraint devices_user_fk
        foreign key (user_id)
        references private.app_users (id)
        on delete cascade,
    constraint devices_approved_by_device_fk
        foreign key (approved_by_device_id)
        references private.devices (id)
        on delete set null,
    constraint devices_label_length_check check (char_length(label) between 1 and 100),
    constraint devices_spki_length_check
        check (octet_length(signing_public_key_spki) between 1 and 1024),
    constraint devices_fingerprint_length_check check (octet_length(fingerprint) = 32),
    constraint devices_epoch_check check (epoch >= 0),
    constraint devices_status_check check (status in ('active', 'revoked')),
    constraint devices_lifecycle_check check (
        (status = 'active' and revoked_at is null)
        or (status = 'revoked' and revoked_at is not null)
    ),
    constraint devices_created_at_check check (last_seen_at >= created_at),
    constraint devices_not_self_approved_check
        check (approved_by_device_id is null or approved_by_device_id <> id)
);

create table private.app_sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    device_id uuid not null,
    token_hash bytea not null,
    csrf_hash bytea not null,
    epoch integer not null,
    created_at timestamptz not null default current_timestamp,
    last_seen_at timestamptz not null default current_timestamp,
    idle_expires_at timestamptz not null,
    absolute_expires_at timestamptz not null,
    revoked_at timestamptz,
    revocation_reason text,
    constraint app_sessions_token_hash_key unique (token_hash),
    constraint app_sessions_user_device_fk
        foreign key (user_id, device_id)
        references private.devices (user_id, id)
        on delete cascade,
    constraint app_sessions_token_hash_length_check check (octet_length(token_hash) = 32),
    constraint app_sessions_csrf_hash_length_check check (octet_length(csrf_hash) = 32),
    constraint app_sessions_epoch_check check (epoch >= 0),
    constraint app_sessions_last_seen_check check (last_seen_at >= created_at),
    constraint app_sessions_idle_expiry_check check (idle_expires_at > created_at),
    constraint app_sessions_absolute_expiry_check
        check (absolute_expires_at >= idle_expires_at),
    constraint app_sessions_revocation_check check (
        (revoked_at is null and revocation_reason is null)
        or (
            revoked_at is not null
            and revocation_reason in (
                'logout',
                'revoked',
                'expired',
                'recovery',
                'device_revoked',
                'account_deleted',
                'rotation',
                'security'
            )
        )
    )
);

create table private.device_challenges (
    id uuid primary key default gen_random_uuid(),
    device_id uuid not null,
    nonce_hash bytea not null,
    origin text not null,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    attempt_count integer not null default 0,
    constraint device_challenges_device_fk
        foreign key (device_id)
        references private.devices (id)
        on delete cascade,
    constraint device_challenges_nonce_hash_key unique (nonce_hash),
    constraint device_challenges_nonce_hash_length_check check (octet_length(nonce_hash) = 32),
    constraint device_challenges_origin_length_check check (char_length(origin) between 1 and 2048),
    constraint device_challenges_expiry_check check (expires_at > created_at),
    constraint device_challenges_consumed_at_check
        check (consumed_at is null or consumed_at >= created_at),
    constraint device_challenges_attempt_count_check check (attempt_count between 0 and 10)
);

create table private.pairing_requests (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    requested_public_key_spki bytea not null,
    requested_fingerprint bytea not null,
    requested_label text not null,
    request_nonce bytea not null,
    comparison_code_hash bytea not null,
    status text not null default 'pending',
    attempt_count integer not null default 0,
    approved_by_device_id uuid,
    approval_signature bytea,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint pairing_requests_user_fk
        foreign key (user_id)
        references private.app_users (id)
        on delete cascade,
    constraint pairing_requests_approved_by_device_fk
        foreign key (approved_by_device_id)
        references private.devices (id)
        on delete set null,
    constraint pairing_requests_public_key_length_check
        check (octet_length(requested_public_key_spki) between 1 and 1024),
    constraint pairing_requests_fingerprint_length_check
        check (octet_length(requested_fingerprint) = 32),
    constraint pairing_requests_label_length_check
        check (char_length(requested_label) between 1 and 100),
    constraint pairing_requests_nonce_length_check
        check (octet_length(request_nonce) between 16 and 64),
    constraint pairing_requests_code_hash_length_check
        check (octet_length(comparison_code_hash) = 32),
    constraint pairing_requests_status_check
        check (status in ('pending', 'approved', 'rejected', 'expired', 'consumed')),
    constraint pairing_requests_attempt_count_check check (attempt_count between 0 and 10),
    constraint pairing_requests_expiry_check check (expires_at > created_at),
    constraint pairing_requests_consumed_at_check
        check (consumed_at is null or consumed_at >= created_at),
    constraint pairing_requests_approval_fields_check check (
        (
            status in ('approved', 'consumed')
            and approved_by_device_id is not null
            and approval_signature is not null
        )
        or (
            status in ('pending', 'rejected', 'expired')
            and approved_by_device_id is null
            and approval_signature is null
        )
    ),
    constraint pairing_requests_approval_signature_length_check
        check (approval_signature is null or octet_length(approval_signature) between 32 and 256),
    constraint pairing_requests_consumption_check check (
        (status = 'consumed' and consumed_at is not null)
        or (status <> 'consumed' and consumed_at is null)
    )
);

create table private.transfer_requests (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    sender_device_id uuid not null,
    recipient_device_id uuid not null,
    protocol_version smallint not null default 1,
    status text not null default 'offered',
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    accepted_at timestamptz,
    completed_at timestamptz,
    failure_code text,
    relay_used boolean not null default false,
    constraint transfer_requests_user_fk
        foreign key (user_id)
        references private.app_users (id)
        on delete cascade,
    constraint transfer_requests_sender_device_fk
        foreign key (user_id, sender_device_id)
        references private.devices (user_id, id)
        on delete cascade,
    constraint transfer_requests_recipient_device_fk
        foreign key (user_id, recipient_device_id)
        references private.devices (user_id, id)
        on delete cascade,
    constraint transfer_requests_distinct_devices_check
        check (sender_device_id <> recipient_device_id),
    constraint transfer_requests_protocol_version_check check (protocol_version between 1 and 32767),
    constraint transfer_requests_status_check check (
        status in (
            'offered',
            'accepted',
            'negotiating',
            'connected',
            'transferring',
            'completed',
            'rejected',
            'expired',
            'cancelled',
            'failed'
        )
    ),
    constraint transfer_requests_created_expiry_check check (expires_at > created_at),
    constraint transfer_requests_accepted_at_check
        check (accepted_at is null or accepted_at >= created_at),
    constraint transfer_requests_completed_at_check
        check (completed_at is null or completed_at >= coalesce(accepted_at, created_at)),
    constraint transfer_requests_completed_status_check
        check ((status = 'completed') = (completed_at is not null)),
    constraint transfer_requests_failure_code_check check (
        (status = 'failed' and failure_code is not null and char_length(failure_code) between 1 and 64)
        or (status <> 'failed' and failure_code is null)
    ),
    constraint transfer_requests_acceptance_status_check check (
        status in ('offered', 'rejected', 'expired')
        or accepted_at is not null
    )
);

create table private.websocket_tickets (
    id uuid primary key default gen_random_uuid(),
    session_id uuid not null,
    token_hash bytea not null,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint websocket_tickets_session_fk
        foreign key (session_id)
        references private.app_sessions (id)
        on delete cascade,
    constraint websocket_tickets_token_hash_key unique (token_hash),
    constraint websocket_tickets_token_hash_length_check check (octet_length(token_hash) = 32),
    constraint websocket_tickets_expiry_check check (expires_at > created_at),
    constraint websocket_tickets_consumed_at_check
        check (consumed_at is null or consumed_at >= created_at)
);

create table private.security_events (
    id uuid primary key default gen_random_uuid(),
    user_id uuid,
    device_id uuid,
    event_type text not null,
    outcome text not null,
    network_fingerprint bytea,
    details jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    constraint security_events_user_fk
        foreign key (user_id)
        references private.app_users (id)
        on delete set null,
    constraint security_events_device_fk
        foreign key (device_id)
        references private.devices (id)
        on delete set null,
    constraint security_events_event_type_check check (
        event_type in (
            'otp_started',
            'otp_verified',
            'otp_failed',
            'session_created',
            'session_revoked',
            'device_challenge_issued',
            'device_challenge_failed',
            'device_registered',
            'device_revoked',
            'pairing_created',
            'pairing_approved',
            'pairing_rejected',
            'pairing_failed',
            'recovery_completed',
            'transfer_created',
            'transfer_failed',
            'turn_credential_issued',
            'rate_limited',
            'security_alert'
        )
    ),
    constraint security_events_outcome_check check (outcome in ('success', 'failure', 'blocked')),
    constraint security_events_network_fingerprint_length_check
        check (network_fingerprint is null or octet_length(network_fingerprint) = 32),
    constraint security_events_details_object_check check (jsonb_typeof(details) = 'object'),
    constraint security_events_details_size_check check (octet_length(details::text) <= 2048),
    constraint security_events_expiry_check check (expires_at >= created_at)
);

create table private.rate_limit_buckets (
    scope text not null,
    bucket_key bytea not null,
    window_started_at timestamptz not null default current_timestamp,
    window_expires_at timestamptz not null,
    request_count integer not null default 0,
    constraint rate_limit_buckets_pk primary key (scope, bucket_key),
    constraint rate_limit_buckets_scope_length_check check (char_length(scope) between 1 and 64),
    constraint rate_limit_buckets_key_length_check check (octet_length(bucket_key) = 32),
    constraint rate_limit_buckets_window_check check (window_expires_at > window_started_at),
    constraint rate_limit_buckets_request_count_check check (request_count >= 0)
);

create index devices_active_by_user_idx
    on private.devices (user_id, last_seen_at desc)
    where status = 'active';
create index app_sessions_expiry_idx
    on private.app_sessions (idle_expires_at, absolute_expires_at);
create index app_sessions_revoked_at_idx
    on private.app_sessions (revoked_at)
    where revoked_at is not null;
create index app_sessions_user_device_idx
    on private.app_sessions (user_id, device_id);
create index device_challenges_expiry_idx
    on private.device_challenges (expires_at);
create index device_challenges_device_expiry_idx
    on private.device_challenges (device_id, expires_at);
create index pairing_requests_expiry_idx
    on private.pairing_requests (expires_at);
create index pairing_requests_user_status_idx
    on private.pairing_requests (user_id, status, created_at desc);
create unique index pairing_requests_pending_fingerprint_idx
    on private.pairing_requests (user_id, requested_fingerprint)
    where status = 'pending';
create index transfer_requests_expiry_idx
    on private.transfer_requests (expires_at);
create index transfer_requests_user_status_idx
    on private.transfer_requests (user_id, status, created_at desc);
create index transfer_requests_sender_status_idx
    on private.transfer_requests (sender_device_id, status, expires_at);
create index transfer_requests_recipient_status_idx
    on private.transfer_requests (recipient_device_id, status, expires_at);
create index websocket_tickets_expiry_idx
    on private.websocket_tickets (expires_at);
create index websocket_tickets_session_expiry_idx
    on private.websocket_tickets (session_id, expires_at);
create index security_events_expiry_idx
    on private.security_events (expires_at);
create index security_events_user_created_idx
    on private.security_events (user_id, created_at desc);
create index rate_limit_buckets_expiry_idx
    on private.rate_limit_buckets (window_expires_at);

-- Keep the private schema closed by default for future migrations as well.
alter default privileges in schema private
    revoke all on tables from public, anon, authenticated;
alter default privileges in schema private
    revoke all on functions from public, anon, authenticated;

revoke all on all tables in schema private from public, anon, authenticated;
revoke all on all functions in schema private from public, anon, authenticated;

grant usage on schema private to app_runtime;
grant select, insert, update, delete on table
    private.app_users,
    private.devices,
    private.app_sessions,
    private.device_challenges,
    private.pairing_requests,
    private.transfer_requests,
    private.websocket_tickets,
    private.security_events,
    private.rate_limit_buckets
    to app_runtime;
