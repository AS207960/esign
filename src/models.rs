use crate::schema::*;

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="templates"]
pub struct Template {
    pub id: uuid::Uuid,
    pub name: String,
    pub base_file: String,
    pub default_subject: Option<String>,
    pub default_message: Option<String>,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="template_fields"]
pub struct TemplateField {
    pub id: uuid::Uuid,
    pub template_id: uuid::Uuid,
    pub signing_order: i64,
    pub field_type: super::schema::FieldType,
    pub required: bool,
    pub page: i64,
    pub top_offset: f64,
    pub left_offset: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="envelopes"]
pub struct Envelope {
    pub id: uuid::Uuid,
    pub template_id: uuid::Uuid,
    pub base_file: String,
    pub current_file: String,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="envelope_recipients"]
pub struct EnvelopeRecipient {
    pub id: uuid::Uuid,
    pub envelope_id: uuid::Uuid,
    pub email: String,
    pub recipient_order: i64,
    pub key: String,
    pub completed: bool,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="envelope_log"]
pub struct EnvelopeLog {
    pub id: uuid::Uuid,
    pub envelope_id: uuid::Uuid,
    pub timestamp: chrono::NaiveDateTime,
    pub recipient_id: uuid::Uuid,
    pub entry_type: crate::schema::LogEntryType,
    #[serde(serialize_with = "ip_only")]
    pub ip_address: ipnetwork::IpNetwork,
    pub user_agent: String,
    pub current_file: String,
    #[serde(serialize_with = "hex_encode")]
    pub current_document_hash: Vec<u8>,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Serialize, Deserialize, Clone, Debug)]
#[table_name="session"]
pub struct Session {
    pub id: uuid::Uuid,
    pub access_token: String,
    pub expires_at: Option<chrono::NaiveDateTime>,
    pub refresh_token: Option<String>,
    pub claims: String,
}

fn hex_encode<S: serde::Serializer>(val: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(val))
}

fn ip_only<S: serde::Serializer>(val: &ipnetwork::IpNetwork, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&val.ip().to_string())
}
