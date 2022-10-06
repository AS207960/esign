#[derive(DbEnum, Serialize, Deserialize, Clone, Debug)]
pub enum FieldType {
    Signature,
    Text,
    Date,
    Checkbox,
}

impl ToString for FieldType {
    fn to_string(&self) -> String {
        match self {
            Self::Signature => "signature",
            Self::Text => "text",
            Self::Date => "date",
            Self::Checkbox => "checkbox"
        }.to_string()
    }
}

#[derive(DbEnum, Serialize, Deserialize, Clone, Debug)]
pub enum LogEntryType {
    Created,
    Opened,
    Downloaded,
    Signed,
}

table! {
    template_fields (id) {
        id -> Uuid,
        template_id -> Uuid,
        signing_order -> Int8,
        field_type -> crate::schema::FieldTypeMapping,
        required -> Bool,
        page -> Int8,
        top_offset -> Float8,
        left_offset -> Float8,
        width -> Float8,
        height -> Float8,
    }
}

table! {
    templates (id) {
        id -> Uuid,
        name -> Varchar,
        base_file -> Varchar,
        default_subject -> Nullable<Varchar>,
        default_message -> Nullable<Varchar>,
    }
}

table! {
    envelopes (id) {
        id -> Uuid,
        template_id -> Uuid,
        base_file -> Varchar,
        current_file -> Varchar,
    }
}

table! {
    envelope_recipients (id) {
        id -> Uuid,
        envelope_id -> Uuid,
        email -> Varchar,
        recipient_order -> Int8,
        key -> Varchar,
        completed -> Bool,
    }
}

table! {
    envelope_log (id) {
        id -> Uuid,
        envelope_id -> Uuid,
        timestamp -> Timestamp,
        recipient_id -> Uuid,
        entry_type -> crate::schema::LogEntryTypeMapping,
        ip_address -> Inet,
        user_agent -> Varchar,
        current_file -> Varchar,
        current_document_hash -> Bytea,
    }
}

table! {
    session (id) {
        id -> Uuid,
        access_token -> Varchar,
        expires_at -> Nullable<Timestamp>,
        refresh_token -> Nullable<Varchar>,
        claims -> Varchar,
    }
}

joinable!(template_fields -> templates (template_id));
joinable!(envelopes -> templates (template_id));
joinable!(envelope_recipients -> envelopes (envelope_id));
joinable!(envelope_log -> envelopes (envelope_id));
joinable!(envelope_log -> envelope_recipients (recipient_id));

allow_tables_to_appear_in_same_query!(
    template_fields,
    templates,
    envelopes,
    envelope_recipients,
    envelope_log,
    session,
);
