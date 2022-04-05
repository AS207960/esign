CREATE TABLE envelopes (
    id           UUID PRIMARY KEY,
    template_id  UUID REFERENCES templates (id),
    base_file    VARCHAR NOT NULL,
    current_file VARCHAR NOT NULL
);

CREATE TABLE envelope_recipients (
    id              UUID PRIMARY KEY,
    envelope_id UUID REFERENCES envelopes (id),
    email           VARCHAR NOT NULL,
    recipient_order INTEGER NOT NULL,
    key             VARCHAR NOT NULL,
    completed       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TYPE log_entry_type AS ENUM ('created', 'opened', 'downloaded', 'signed');

CREATE TABLE envelope_log (
    id UUID PRIMARY KEY,
    envelope_id UUID REFERENCES envelopes (id),
    timestamp TIMESTAMP NOT NULL,
    recipient_id UUID REFERENCES envelope_recipients (id),
    entry_type log_entry_type NOT NULL,
    ip_address inet NOT NULL,
    user_agent VARCHAR NOT NULL,
    current_file VARCHAR NOT NULL,
    current_document_hash bytea NOT NULL
);