-- A public-key fingerprint identifies one browser credential within an account.
create unique index devices_user_fingerprint_idx
    on private.devices (user_id, fingerprint);
