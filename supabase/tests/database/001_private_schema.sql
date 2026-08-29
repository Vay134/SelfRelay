-- pgTAP is only enabled in the disposable database used by this test suite.
create schema if not exists extensions;
create extension if not exists pgtap with schema extensions;

begin;

set local search_path = extensions, pg_catalog, public;

select plan(26);

select has_table('private', 'app_users', 'private.app_users exists');
select has_table('private', 'devices', 'private.devices exists');
select has_table('private', 'app_sessions', 'private.app_sessions exists');
select has_table('private', 'device_challenges', 'private.device_challenges exists');
select has_table('private', 'pairing_requests', 'private.pairing_requests exists');
select has_table('private', 'transfer_requests', 'private.transfer_requests exists');
select has_table('private', 'websocket_tickets', 'private.websocket_tickets exists');
select has_table('private', 'security_events', 'private.security_events exists');
select has_table('private', 'rate_limit_buckets', 'private.rate_limit_buckets exists');

select ok(
    (
        select count(*) = 9
        from pg_catalog.pg_class as relation
        join pg_catalog.pg_namespace as schema on schema.oid = relation.relnamespace
        where schema.nspname = 'private'
            and relation.relkind = 'r'
    ),
    'private contains exactly the nine application tables'
);

select ok(
    (
        select count(*) = 6
        from pg_catalog.pg_constraint as constraint_row
        join pg_catalog.pg_class as relation
            on relation.oid = constraint_row.conrelid
        join pg_catalog.pg_namespace as schema
            on schema.oid = relation.relnamespace
        where schema.nspname = 'private'
            and constraint_row.conname in (
                'app_users_supabase_user_id_key',
                'app_users_email_normalized_key',
                'devices_user_id_id_key',
                'app_sessions_user_device_fk',
                'transfer_requests_sender_device_fk',
                'transfer_requests_recipient_device_fk'
            )
    ),
    'identity, uniqueness, and account-ownership constraints exist'
);

select has_index(
    'private',
    'devices',
    'devices_active_by_user_idx',
    'active-device lookup index exists'
);
select has_index(
    'private',
    'app_sessions',
    'app_sessions_expiry_idx',
    'session expiry index exists'
);
select has_index(
    'private',
    'device_challenges',
    'device_challenges_expiry_idx',
    'challenge expiry index exists'
);
select has_index(
    'private',
    'pairing_requests',
    'pairing_requests_expiry_idx',
    'pairing expiry index exists'
);
select has_index(
    'private',
    'transfer_requests',
    'transfer_requests_expiry_idx',
    'transfer expiry index exists'
);
select has_index(
    'private',
    'websocket_tickets',
    'websocket_tickets_expiry_idx',
    'WebSocket ticket expiry index exists'
);
select has_index(
    'private',
    'security_events',
    'security_events_expiry_idx',
    'security-event expiry index exists'
);
select has_index(
    'private',
    'rate_limit_buckets',
    'rate_limit_buckets_expiry_idx',
    'rate-limit expiry index exists'
);

select ok(
    has_schema_privilege('app_runtime', 'private', 'USAGE')
        and not has_schema_privilege('app_runtime', 'private', 'CREATE'),
    'app_runtime can use but cannot create in private'
);

select ok(
    (
        select bool_and(has_table_privilege('app_runtime', table_name, 'SELECT'))
        from (
            values
                ('private.app_users'::text),
                ('private.devices'::text),
                ('private.app_sessions'::text),
                ('private.device_challenges'::text),
                ('private.pairing_requests'::text),
                ('private.transfer_requests'::text),
                ('private.websocket_tickets'::text),
                ('private.security_events'::text),
                ('private.rate_limit_buckets'::text)
        ) as tables(table_name)
    ),
    'app_runtime can select every application table'
);

select ok(
    (
        select bool_and(
            has_table_privilege('app_runtime', table_name, 'INSERT')
            and has_table_privilege('app_runtime', table_name, 'UPDATE')
            and has_table_privilege('app_runtime', table_name, 'DELETE')
        )
        from (
            values
                ('private.app_users'::text),
                ('private.devices'::text),
                ('private.app_sessions'::text),
                ('private.device_challenges'::text),
                ('private.pairing_requests'::text),
                ('private.transfer_requests'::text),
                ('private.websocket_tickets'::text),
                ('private.security_events'::text),
                ('private.rate_limit_buckets'::text)
        ) as tables(table_name)
    )
        and not has_table_privilege('app_runtime', 'private.app_users', 'TRUNCATE')
        and not has_table_privilege('app_runtime', 'private.app_users', 'REFERENCES')
        and not has_table_privilege('app_runtime', 'private.app_users', 'TRIGGER'),
    'app_runtime has only table DML privileges'
);

select ok(
    not has_schema_privilege('anon', 'private', 'USAGE')
        and not has_schema_privilege('authenticated', 'private', 'USAGE'),
    'browser roles cannot use private'
);

select ok(
    not has_table_privilege('anon', 'private.app_users', 'SELECT')
        and not has_table_privilege('authenticated', 'private.app_users', 'SELECT')
        and not has_table_privilege('anon', 'private.devices', 'SELECT')
        and not has_table_privilege('authenticated', 'private.devices', 'SELECT'),
    'browser roles cannot select application tables'
);

select ok(
    not exists (
        select 1
        from pg_catalog.pg_class as relation
        join pg_catalog.pg_namespace as schema on schema.oid = relation.relnamespace
        cross join lateral aclexplode(
            coalesce(relation.relacl, acldefault('r', relation.relowner))
        ) as privilege
        where schema.nspname = 'private'
            and relation.relkind = 'r'
            and privilege.grantee = 0
            and privilege.privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    ),
    'PUBLIC has no DML privileges on private tables'
);

insert into auth.users (id, aud, role, email)
values
    ('00000000-0000-0000-0000-000000000001', 'authenticated', 'authenticated', 'one@example.test'),
    ('00000000-0000-0000-0000-000000000002', 'authenticated', 'authenticated', 'two@example.test');

insert into private.app_users (id, supabase_user_id, email_normalized)
values
    (
        '10000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001',
        'one@example.test'
    ),
    (
        '10000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000002',
        'two@example.test'
    );

insert into private.devices (
    id,
    user_id,
    epoch,
    label,
    signing_public_key_spki,
    fingerprint
)
values
    (
        '20000000-0000-0000-0000-000000000001',
        '10000000-0000-0000-0000-000000000001',
        0,
        'first device',
        decode(repeat('ab', 91), 'hex'),
        decode(repeat('cd', 32), 'hex')
    ),
    (
        '20000000-0000-0000-0000-000000000002',
        '10000000-0000-0000-0000-000000000002',
        0,
        'second device',
        decode(repeat('ef', 91), 'hex'),
        decode(repeat('12', 32), 'hex')
    );

select throws_ok(
    $$
        insert into private.transfer_requests (
            user_id,
            sender_device_id,
            recipient_device_id,
            expires_at
        )
        values (
            '10000000-0000-0000-0000-000000000001',
            '20000000-0000-0000-0000-000000000001',
            '20000000-0000-0000-0000-000000000002',
            current_timestamp + interval '10 minutes'
        )
    $$,
    '23503',
    'insert or update on table "transfer_requests" violates foreign key constraint "transfer_requests_recipient_device_fk"'
);

select * from finish();

rollback;
