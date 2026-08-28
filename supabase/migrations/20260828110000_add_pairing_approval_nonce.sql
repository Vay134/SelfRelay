alter table private.pairing_requests
    add column approval_nonce bytea;

alter table private.pairing_requests
    add constraint pairing_requests_approval_nonce_length_check
    check (approval_nonce is null or octet_length(approval_nonce) = 32);

alter table private.pairing_requests
    add constraint pairing_requests_approval_nonce_status_check
    check (
        (status in ('approved', 'consumed') and approval_nonce is not null)
        or (status in ('pending', 'rejected', 'expired') and approval_nonce is null)
    );
