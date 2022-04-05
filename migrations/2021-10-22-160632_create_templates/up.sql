CREATE TABLE templates
(
    id              UUID PRIMARY KEY,
    name            VARCHAR NOT NULL,
    base_file       VARCHAR NOT NULL,
    default_subject VARCHAR,
    default_message VARCHAR
);

CREATE TYPE field_type AS ENUM('signature', 'text', 'date', 'checkbox');
CREATE TABLE template_fields
(
    id            UUID PRIMARY KEY,
    template_id   UUID NOT NULL REFERENCES templates (id),
    signing_order INTEGER NOT NULL,
    field_type    field_type NOT NULL,
    required      BOOLEAN NOT NULL,
    page          INTEGER NOT NULL,
    top_offset    DOUBLE PRECISION NOT NULL,
    left_offset   DOUBLE PRECISION NOT NULL,
    width         DOUBLE PRECISION NOT NULL,
    height        DOUBLE PRECISION NOT NULL
);