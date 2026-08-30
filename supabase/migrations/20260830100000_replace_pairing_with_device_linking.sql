-- Replace the old two-screen approval request with a one-time device-linking code.

alter table private.app_users
    rename column recovered_at to email_fallback_at;

alter table private.app_users
    rename constraint app_users_recovered_at_check to app_users_email_fallback_at_check;

alter table private.devices
    drop constraint devices_not_self_approved_check,
    drop constraint devices_lifecycle_check,
    drop constraint devices_status_check,
    drop column approved_by_device_id;

alter table private.devices
    add column linked_by_device_id uuid,
    add constraint devices_linked_by_device_fk
        foreign key (linked_by_device_id)
        references private.devices (id)
        on delete set null,
    add constraint devices_status_check
        check (status in ('active', 'inactive', 'revoked')),
    add constraint devices_lifecycle_check check (
        (status in ('active', 'inactive') and revoked_at is null)
        or (status = 'revoked' and revoked_at is not null)
    ),
    add constraint devices_not_self_linked_check
        check (linked_by_device_id is null or linked_by_device_id <> id);

create table private.device_linking_otps (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    issuing_device_id uuid not null,
    otp_hash bytea not null,
    status text not null default 'active',
    attempt_count integer not null default 0,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint device_linking_otps_user_fk
        foreign key (user_id)
        references private.app_users (id)
        on delete cascade,
    constraint device_linking_otps_issuing_device_fk
        foreign key (user_id, issuing_device_id)
        references private.devices (user_id, id)
        on delete cascade,
    constraint device_linking_otps_hash_key unique (otp_hash),
    constraint device_linking_otps_hash_length_check check (octet_length(otp_hash) = 32),
    constraint device_linking_otps_status_check
        check (status in ('active', 'consumed', 'expired')),
    constraint device_linking_otps_attempt_count_check check (attempt_count between 0 and 10),
    constraint device_linking_otps_expiry_check check (expires_at > created_at),
    constraint device_linking_otps_consumed_at_check
        check (consumed_at is null or consumed_at >= created_at),
    constraint device_linking_otps_consumption_check check (
        (status = 'consumed' and consumed_at is not null)
        or (status in ('active', 'expired') and consumed_at is null)
    )
);

drop table private.pairing_requests;

alter table private.security_events
    drop constraint security_events_event_type_check;

alter table private.security_events
    add constraint security_events_event_type_check check (
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
            'device_logged_out',
            'device_linking_otp_created',
            'device_linking_failed',
            'device_linked',
            'email_fallback_completed',
            'transfer_created',
            'transfer_failed',
            'turn_credential_issued',
            'rate_limited',
            'security_alert'
        )
    );

create index device_linking_otps_expiry_idx
    on private.device_linking_otps (expires_at);
create index device_linking_otps_user_status_idx
    on private.device_linking_otps (user_id, status, created_at desc);

revoke all on table private.device_linking_otps from public, anon, authenticated;
grant select, insert, update, delete on table private.device_linking_otps to app_runtime;
