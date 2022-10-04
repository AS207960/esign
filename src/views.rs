pub use crate::files::{files, authenticated_files};
use crate::files::FileKey;
use crate::{models, csrf, schema, tasks, DbConn, Config, CeleryApp};
use rocket_dyn_templates::Template;
use rocket::serde::json::Json;
use itertools::Itertools;
use diesel::prelude::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientMeta {
    pub ip: std::net::IpAddr,
    pub user_agent: String,
}

#[rocket::async_trait]
impl<'r> rocket::request::FromRequest<'r> for ClientMeta {
    type Error = &'static str;

    async fn from_request(request: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let config = match request.guard::<&rocket::State<crate::Config>>().await {
            rocket::request::Outcome::Success(c) => c,
            rocket::request::Outcome::Forward(f) => return rocket::request::Outcome::Forward(f),
            rocket::request::Outcome::Failure(_) => return rocket::request::Outcome::Failure((rocket::http::Status::InternalServerError, "Unable to get config")),
        };


        let mut ip = match rocket_client_addr::ClientRealAddr::from_request(request).await {
            rocket::request::Outcome::Success(ip) => ip.ip,
            rocket::request::Outcome::Forward(f) => return rocket::request::Outcome::Forward(f),
            rocket::request::Outcome::Failure(_) => return rocket::request::Outcome::Failure((rocket::http::Status::BadRequest, "Unable to ascertain client IP")),
        };

        if let std::net::IpAddr::V6(v6_ip) = ip {
            if let Some(v4_ip) = v6_ip.to_ipv4() {
                ip = std::net::IpAddr::V4(v4_ip);
            } else if let Some(nat64_net) = config.nat64_net {
                if nat64_net.contains(&v6_ip) {
                    let [_, _, _, _, _, _, ab, cd] = v6_ip.segments();
                    let [a, b] = ab.to_be_bytes();
                    let [c, d] = cd.to_be_bytes();
                    ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
                }
            }
        }

        let user_agent = match request.headers().get_one("User-Agent") {
            Some(v) => v.to_string(),
            None => return rocket::request::Outcome::Failure((rocket::http::Status::BadRequest, "Unable to ascertain client user agent"))
        };

        rocket::request::Outcome::Success(ClientMeta {
            ip,
            user_agent,
        })
    }
}

pub type TemplateID = crate::TypedUUIDField<"esign_template">;
pub type EnvelopeID = crate::TypedUUIDField<"esign_envelope">;
pub type RecipientID = crate::TypedUUIDField<"esign_recipient">;

#[get("/template", rank = 2)]
pub async fn templates_no_auth(
    origin: &rocket::http::uri::Origin<'_>, oidc_app: &rocket::State<crate::oidc::OIDCApplication>, config: &rocket::State<Config>,
) -> crate::oidc::OIDCAuthorizeRedirect {
    oidc_app.authorize(&origin.to_string(), &config.external_uri.to_string()).unwrap()
}

#[derive(Serialize)]
struct TemplatesContext {
    templates: Vec<TemplatesContextTemplate>,
    user_authenticated: bool,
    can_send: bool,
}

#[derive(Serialize)]
struct TemplatesContextTemplate {
    template_id: String,
    template: models::Template,
    url: String,
}

#[get("/template", rank = 1)]
pub async fn templates(
    db: DbConn, oidc_user: crate::oidc::OIDCUser, oidc_app: &rocket::State<crate::oidc::OIDCApplication>,
) -> Result<Template, rocket::http::Status> {
    if !oidc_user.claims.additional_claims().has_role(oidc_app.client_id(), "view-envelopes") {
        return Err(rocket::http::Status::Forbidden);
    }

    let templates = crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::templates::dsl::templates.load::<models::Template>(c)
    }).await?;

    Ok(Template::render("templates", TemplatesContext {
        templates: templates.into_iter().map(|t| {
            let id = TemplateID {
                uuid: t.id.clone()
            };
            TemplatesContextTemplate {
                url: rocket::uri!(template(tid = &id)).to_string(),
                template_id: id.to_string(),
                template: t,
            }
        }).collect(),
        user_authenticated: true,
        can_send: oidc_user.claims.additional_claims().has_role(oidc_app.client_id(), "send-envelopes")
    }))
}

#[derive(Serialize)]
struct TemplateContext {
    template_id: String,
    template: models::Template,
    file_key: String,
    own_fields: std::collections::HashMap<String, Vec<FieldContext>>,
    other_fields: Vec<std::collections::HashMap<String, Vec<FieldContext>>>,
    num_recipients: usize,
    csrf_token: String,
    user_authenticated: bool,
}

#[derive(Serialize, Debug)]
struct FieldContext {
    id: String,
    field_type: String,
    top: f64,
    left: f64,
    width: f64,
    height: f64,
    required: bool,
}

impl From<&models::TemplateField> for FieldContext {
    fn from(f: &models::TemplateField) -> Self {
        Self {
            id: f.id.to_string(),
            field_type: f.field_type.to_string(),
            top: f.top_offset,
            left: f.left_offset,
            width: f.width,
            height: f.height,
            required: f.required,
        }
    }
}

async fn load_template(tid: uuid::Uuid, db: &DbConn) -> Result<(models::Template, Vec<models::TemplateField>), rocket::http::Status> {
    let db_res = crate::db_run(db, move |c| -> diesel::result::QueryResult<_> {
        Ok((
            schema::templates::dsl::templates.find(tid).first::<models::Template>(c).optional()?,
            schema::template_fields::dsl::template_fields.filter(
                schema::template_fields::dsl::template_id.eq(tid)
            ).load::<models::TemplateField>(c)?
        ))
    }).await?;

    Ok(match db_res {
        (Some(t), f) => (t, f),
        (None, _) => return Err(rocket::http::Status::NotFound),
    })
}

async fn load_envelope(eid: uuid::Uuid, db: &DbConn) -> Result<models::Envelope, rocket::http::Status> {
    let db_res = crate::db_run(db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelopes::dsl::envelopes.find(eid).first::<models::Envelope>(c).optional()
    }).await?;

    Ok(match db_res {
        Some(e) => e,
        None => return Err(rocket::http::Status::NotFound),
    })
}

#[get("/template/<_>", rank = 2)]
pub async fn template_no_auth(
    origin: &rocket::http::uri::Origin<'_>, oidc_app: &rocket::State<crate::oidc::OIDCApplication>,
    config: &rocket::State<Config>,
) -> crate::oidc::OIDCAuthorizeRedirect {
    oidc_app.authorize(&origin.to_string(), &config.external_uri.to_string()).unwrap()
}

#[get("/template/<tid>", rank = 1)]
pub async fn template(
    tid: TemplateID, db: DbConn, csrf_token: csrf::CSRFToken, oidc_user: crate::oidc::OIDCUser,
    config: &rocket::State<Config>,
) -> Result<Template, rocket::http::Status> {
    if !oidc_user.claims.additional_claims().has_role(&config.oidc.client_id, "send-envelopes") {
        return Err(rocket::http::Status::Forbidden);
    }

    let (template, fields) = load_template(tid.uuid, &db).await?;
    debug!("Loaded template and fields: {:#?}, {:#?}", template, fields);

    let mut own_fields = std::collections::HashMap::<String, Vec<FieldContext>>::new();
    for field in fields.iter().filter(|f| f.signing_order == 0) {
        let field_context: FieldContext = field.into();
        match own_fields.get_mut(&field.page.to_string()) {
            Some(v) => {
                v.push(field_context);
            }
            None => {
                own_fields.insert(field.page.to_string(), vec![field_context]);
            }
        }
    }
    let mut other_fields_db = fields.iter().filter(|f| f.signing_order != 0).collect::<Vec<_>>();
    other_fields_db.sort_by(|f1, f2| f1.signing_order.cmp(&f2.signing_order));
    let other_fields = other_fields_db.into_iter().group_by(|f| f.signing_order).into_iter().map(|(_, f)| {
        let mut fields = std::collections::HashMap::<String, Vec<FieldContext>>::new();
        for field in f {
            let field_context: FieldContext = field.into();
            match fields.get_mut(&field.page.to_string()) {
                Some(v) => {
                    v.push(field_context);
                }
                None => {
                    fields.insert(field.page.to_string(), vec![field_context]);
                }
            }
        }
        fields
    }).collect::<Vec<_>>();

    Ok(Template::render("template", TemplateContext {
        file_key: FileKey::new(&template.base_file, &config.files_key).to_string(),
        template_id: TemplateID {
            uuid: template.id.clone()
        }.to_string(),
        template,
        own_fields,
        num_recipients: other_fields.len(),
        other_fields,
        csrf_token: csrf_token.to_string(),
        user_authenticated: true,
    }))
}

#[derive(Deserialize)]
pub struct TemplateSubmitData {
    csrf_token: String,
    recipients: Vec<String>,
    fields: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
pub struct TemplateSubmitResp {
    envelope_id: String,
}

#[post("/template/<_>/create", rank = 2)]
pub fn template_submit_no_auth() -> rocket::http::Status {
    rocket::http::Status::Forbidden
}

#[post("/template/<tid>/create", data = "<data>", format = "application/json", rank = 1)]
pub async fn template_submit<'a>(
    config: &'a rocket::State<Config>, tid: TemplateID, db: DbConn, csrf_token: csrf::CSRFToken,
    celery_app: &'a rocket::State<CeleryApp>, client_meta: ClientMeta,
    mut data: Json<TemplateSubmitData>, oidc_user: crate::oidc::OIDCUser,
) -> Result<Json<TemplateSubmitResp>, rocket::http::Status> {
    if !csrf_token.verify(&data.csrf_token) {
        return Err(rocket::http::Status::Forbidden);
    }

    if !oidc_user.claims.additional_claims().has_role(&config.oidc.client_id, "send-envelopes") {
        return Err(rocket::http::Status::Forbidden);
    }

    let (template, fields) = load_template(tid.uuid, &db).await?;

    let mut other_fields_db = fields.iter().filter(|f| f.signing_order != 0).collect::<Vec<_>>();
    other_fields_db.sort_by(|f1, f2| f1.signing_order.cmp(&f2.signing_order));
    let num_recipients = other_fields_db.into_iter().group_by(|f| f.signing_order).into_iter().collect::<Vec<_>>().len();

    if data.recipients.len() != num_recipients {
        return Err(rocket::http::Status::BadRequest);
    }

    let own_fields = fields.into_iter().filter(|f| f.signing_order == 0).collect::<Vec<_>>();

    let mut field_values = vec![];
    for field in own_fields {
        let field_value = match data.fields.remove(&field.id.to_string()) {
            Some(v) => v,
            None => return Err(rocket::http::Status::BadRequest)
        };
        if field.required && field_value.is_empty() {
            return Err(rocket::http::Status::BadRequest);
        }
        field_values.push((field, field_value));
    }

    let new_envelope = models::Envelope {
        id: uuid::Uuid::new_v4(),
        template_id: template.id.clone(),
        base_file: template.base_file.clone(),
        current_file: template.base_file.clone(),
    };
    let own_recipient_id = uuid::Uuid::new_v4();
    let own_recipient = models::EnvelopeRecipient {
        id: own_recipient_id.clone(),
        envelope_id: new_envelope.id.clone(),
        email: oidc_user.claims.email().map(|e| e.to_string()).unwrap_or_default(),
        recipient_order: 0,
        key: tasks::make_recipient_key(),
        completed: true,
    };
    let mut new_recipients = vec![own_recipient.clone()];

    for (i, recipient_email) in data.recipients.iter().enumerate() {
        let recipient_email = match recipient_email.parse::<lettre::address::Address>() {
            Ok(e) => e,
            Err(_) => return Err(rocket::http::Status::BadRequest)
        };

        new_recipients.push(models::EnvelopeRecipient {
            id: uuid::Uuid::new_v4(),
            envelope_id: new_envelope.id.clone(),
            email: recipient_email.to_string(),
            recipient_order: (i + 1) as i32,
            key: tasks::make_recipient_key(),
            completed: false,
        });
    };

    let log_entry = models::EnvelopeLog {
        id: uuid::Uuid::new_v4(),
        envelope_id: new_envelope.id.clone(),
        timestamp: chrono::Utc::now().naive_utc(),
        recipient_id: own_recipient_id.clone(),
        entry_type: schema::LogEntryType::Created,
        ip_address: client_meta.ip.into(),
        user_agent: client_meta.user_agent.clone(),
        current_file: template.base_file.clone(),
        current_document_hash: tasks::hash_file(template.base_file).await.ok_or(rocket::http::Status::InternalServerError)?,
    };

    let envelope_id = EnvelopeID {
        uuid: new_envelope.id.clone()
    };

    let task = tasks::sign_envelope::new(new_envelope.clone(), own_recipient, field_values, client_meta);

    crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        c.transaction(|| {
            diesel::insert_into(schema::envelopes::dsl::envelopes)
                .values(&new_envelope)
                .execute(c)?;
            diesel::insert_into(schema::envelope_recipients::dsl::envelope_recipients)
                .values(&new_recipients)
                .execute(c)?;
            diesel::insert_into(schema::envelope_log::dsl::envelope_log)
                .values(&log_entry)
                .execute(c)?;
            Ok(())
        })
    }).await?;

    match celery_app.send_task(task).await {
        Ok(_) => {}
        Err(err) => {
            error!("Failed to submit celery task: {:?}", err);
            return Err(rocket::http::Status::InternalServerError);
        }
    };

    Ok(Json(TemplateSubmitResp {
        envelope_id: envelope_id.to_string()
    }))
}

#[get("/envelope", rank = 2)]
pub async fn envelopes_no_auth(
    origin: &rocket::http::uri::Origin<'_>, oidc_app: &rocket::State<crate::oidc::OIDCApplication>, config: &rocket::State<Config>,
) -> crate::oidc::OIDCAuthorizeRedirect {
    oidc_app.authorize(&origin.to_string(), &config.external_uri.to_string()).unwrap()
}

#[derive(Serialize)]
struct EnvelopesContext {
    envelopes: Vec<EnvelopesContextEnvelope>,
    user_authenticated: bool,
}

#[derive(Serialize)]
struct EnvelopesContextEnvelope {
    envelope_id: String,
    envelope: models::Envelope,
    template: models::Template,
    create_log: models::EnvelopeLog,
    created_recipient: models::EnvelopeRecipient,
    recipients: Vec<models::EnvelopeRecipient>,
    url: String,
}

#[get("/envelope", rank = 1)]
pub async fn envelopes(
    db: DbConn, oidc_user: crate::oidc::OIDCUser, config: &rocket::State<Config>,
) -> Result<Template, rocket::http::Status> {
    if !oidc_user.claims.additional_claims().has_role(&config.oidc.client_id, "view-envelopes") {
        return Err(rocket::http::Status::Forbidden);
    }

    let envelopes = crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelopes::dsl::envelopes
            .inner_join(schema::templates::dsl::templates)
            .inner_join(schema::envelope_log::dsl::envelope_log)
            .filter(schema::envelope_log::dsl::entry_type.eq(schema::LogEntryType::Created))
            .order_by(schema::envelope_log::dsl::timestamp.desc())
            .inner_join(schema::envelope_recipients::dsl::envelope_recipients
                .on(schema::envelope_recipients::dsl::id.eq(schema::envelope_log::dsl::recipient_id))
            )
            .load::<(models::Envelope, models::Template, models::EnvelopeLog, models::EnvelopeRecipient)>(c)
    }).await?;

    let mut envelopes_out = vec![];
    for t in envelopes {
        let id = EnvelopeID {
            uuid: t.0.id.clone()
        };

        let recipients = crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
            schema::envelope_recipients::dsl::envelope_recipients
                .filter(schema::envelope_recipients::dsl::envelope_id.eq(t.0.id))
                .filter(schema::envelope_recipients::dsl::id.ne(t.3.id))
                .order_by(schema::envelope_recipients::dsl::recipient_order.asc())
                .load::<models::EnvelopeRecipient>(c)
        }).await?;

        envelopes_out.push(EnvelopesContextEnvelope {
            url: rocket::uri!(envelope(eid = &id)).to_string(),
            envelope_id: id.to_string(),
            envelope: t.0,
            template: t.1,
            create_log: t.2,
            created_recipient: t.3,
            recipients,
        });
    }

    Ok(Template::render("envelopes", EnvelopesContext {
        envelopes: envelopes_out,
        user_authenticated: true,
    }))
}

#[derive(Serialize)]
struct EnvelopeContext {
    envelope_id: EnvelopeID,
    envelope: models::Envelope,
    template: models::Template,
    recipients: Vec<models::EnvelopeRecipient>,
    log_entries: Vec<(models::EnvelopeLog, models::EnvelopeRecipient, String)>,
    base_file_key: String,
    current_file_key: String,
    csrf_token: String,
    user_authenticated: bool,
}

#[get("/envelope/<_>", rank = 2)]
pub async fn envelope_no_auth(
    origin: &rocket::http::uri::Origin<'_>, oidc_app: &rocket::State<crate::oidc::OIDCApplication>, config: &rocket::State<Config>,
) -> crate::oidc::OIDCAuthorizeRedirect {
    oidc_app.authorize(&origin.to_string(), &config.external_uri.to_string()).unwrap()
}

#[get("/envelope/<eid>", rank = 1)]
pub async fn envelope(
    eid: EnvelopeID, csrf_token: csrf::CSRFToken, oidc_user: crate::oidc::OIDCUser, db: DbConn,
    config: &rocket::State<Config>,
) -> Result<Template, rocket::http::Status> {
    if !oidc_user.claims.additional_claims().has_role(&config.oidc.client_id, "view-envelopes") {
        return Err(rocket::http::Status::Forbidden);
    }

    let envelope = load_envelope(eid.uuid, &db).await?;
    let template = load_template(envelope.template_id, &db).await?;
    let envelope_recipients: Vec<models::EnvelopeRecipient> = crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelope_recipients::dsl::envelope_recipients
            .filter(schema::envelope_recipients::dsl::envelope_id.eq(envelope.id))
            .load::<models::EnvelopeRecipient>(c)
    }).await?;
    let log_entries: Vec<(models::EnvelopeLog, models::EnvelopeRecipient)> = crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelope_log::dsl::envelope_log
            .filter(schema::envelope_log::dsl::envelope_id.eq(envelope.id))
            .inner_join(schema::envelope_recipients::dsl::envelope_recipients)
            .order_by(schema::envelope_log::dsl::timestamp.desc())
            .load::<(models::EnvelopeLog, models::EnvelopeRecipient)>(c)
    }).await?;

    Ok(Template::render("envelope", EnvelopeContext {
        envelope_id: EnvelopeID {
            uuid: eid.uuid.clone()
        },
        base_file_key: FileKey::new(&envelope.base_file, &config.files_key).to_string(),
        current_file_key: FileKey::new(&envelope.current_file, &config.files_key).to_string(),
        envelope,
        template: template.0,
        log_entries: log_entries.into_iter().map(|e| {
            let fk = FileKey::new(&e.0.current_file, &config.files_key).to_string();
            (e.0, e.1, fk)
        }).collect(),
        recipients: envelope_recipients,
        csrf_token: csrf_token.to_string(),
        user_authenticated: true,
    }))
}

#[derive(Serialize)]
struct EnvelopeSignContext {
    envelope_id: EnvelopeID,
    recipient_id: RecipientID,
    template: models::Template,
    envelope: models::Envelope,
    envelope_recipient: models::EnvelopeRecipient,
    file_key: String,
    own_fields: std::collections::HashMap<String, Vec<FieldContext>>,
    csrf_token: String,
    user_authenticated: bool,
}

#[derive(Serialize)]
struct EnvelopeSignCompletedContext {
    template: models::Template,
    envelope: models::Envelope,
    envelope_recipient: models::EnvelopeRecipient,
}

#[get("/envelope/<eid>/sign/<rid>?<key>")]
pub async fn envelope_sign(
    eid: EnvelopeID, rid: RecipientID, key: String, csrf_token: csrf::CSRFToken, db: DbConn,
    config: &rocket::State<Config>, client_meta: ClientMeta, oidc_user: Option<crate::oidc::OIDCUser>,
) -> Result<Template, rocket::http::Status> {
    let envelope = load_envelope(eid.uuid, &db).await?;
    let envelope_recipient: models::EnvelopeRecipient = match crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelope_recipients::dsl::envelope_recipients.find(rid.uuid)
            .filter(schema::envelope_recipients::dsl::envelope_id.eq(envelope.id))
            .first::<models::EnvelopeRecipient>(c).optional()
    }).await? {
        Some(r) => r,
        None => return Err(rocket::http::Status::NotFound)
    };

    if envelope_recipient.key != key {
        return Err(rocket::http::Status::Forbidden);
    }

    let (template, fields) = load_template(envelope.template_id.clone(), &db).await?;

    if envelope_recipient.completed {
        return Ok(Template::render("envelope_sign_completed", EnvelopeSignCompletedContext {
            template,
            envelope,
            envelope_recipient,
        }));
    }

    let mut own_fields = std::collections::HashMap::<String, Vec<FieldContext>>::new();
    for field in fields.iter().filter(|f| f.signing_order == envelope_recipient.recipient_order) {
        let field_context: FieldContext = field.into();
        match own_fields.get_mut(&field.page.to_string()) {
            Some(v) => {
                v.push(field_context);
            }
            None => {
                own_fields.insert(field.page.to_string(), vec![field_context]);
            }
        }
    }

    let log_entry = models::EnvelopeLog {
        id: uuid::Uuid::new_v4(),
        envelope_id: envelope.id.clone(),
        timestamp: chrono::Utc::now().naive_utc(),
        recipient_id: envelope_recipient.id.clone(),
        entry_type: schema::LogEntryType::Opened,
        ip_address: client_meta.ip.into(),
        user_agent: client_meta.user_agent,
        current_file: envelope.current_file.clone(),
        current_document_hash: tasks::hash_file(&envelope.current_file).await.ok_or(rocket::http::Status::InternalServerError)?,
    };
    crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        diesel::insert_into(schema::envelope_log::dsl::envelope_log)
            .values(&log_entry)
            .execute(c)
    }).await?;

    Ok(Template::render("envelope_sign", EnvelopeSignContext {
        envelope_id: EnvelopeID {
            uuid: envelope.id.clone()
        },
        recipient_id: RecipientID {
            uuid: envelope_recipient.id.clone()
        },
        file_key: FileKey::new(&envelope.current_file, &config.files_key).to_string(),
        template,
        envelope,
        envelope_recipient,
        own_fields,
        csrf_token: csrf_token.to_string(),
        user_authenticated: oidc_user.is_some(),
    }))
}


#[derive(Deserialize)]
pub struct EnvelopeSignSubmitData {
    csrf_token: String,
    fields: std::collections::HashMap<String, String>,
    key: String,
}

#[derive(Serialize)]
pub struct EnvelopeSignSubmitResp {}

#[post("/envelope/<eid>/sign/<rid>/create", data = "<data>", format = "application/json")]
pub async fn envelope_sign_submit(
    eid: EnvelopeID, rid: RecipientID, db: DbConn, csrf_token: csrf::CSRFToken, celery_app: &rocket::State<CeleryApp>,
    mut data: Json<EnvelopeSignSubmitData>, client_meta: ClientMeta,
) -> Result<Json<EnvelopeSignSubmitResp>, rocket::http::Status> {
    if !csrf_token.verify(&data.csrf_token) {
        return Err(rocket::http::Status::Forbidden);
    }

    let envelope = load_envelope(eid.uuid, &db).await?;
    let envelope_recipient: models::EnvelopeRecipient = match crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        schema::envelope_recipients::dsl::envelope_recipients.find(rid.uuid)
            .filter(schema::envelope_recipients::dsl::envelope_id.eq(envelope.id))
            .first::<models::EnvelopeRecipient>(c).optional()
    }).await? {
        Some(r) => r,
        None => return Err(rocket::http::Status::NotFound)
    };

    if envelope_recipient.key != data.key {
        return Err(rocket::http::Status::Forbidden);
    }
    if envelope_recipient.completed {
        return Err(rocket::http::Status::Forbidden);
    }

    let (_, fields) = load_template(envelope.template_id.clone(), &db).await?;
    let own_fields = fields.into_iter().filter(|f| f.signing_order == envelope_recipient.recipient_order).collect::<Vec<_>>();

    let mut field_values = vec![];
    for field in own_fields {
        let field_value = match data.fields.remove(&field.id.to_string()) {
            Some(v) => v,
            None => return Err(rocket::http::Status::BadRequest)
        };
        if field.required && field_value.is_empty() {
            return Err(rocket::http::Status::BadRequest);
        }
        field_values.push((field, field_value));
    }

    crate::db_run(&db, move |c| -> diesel::result::QueryResult<_> {
        diesel::update(schema::envelope_recipients::dsl::envelope_recipients.filter(
            schema::envelope_recipients::dsl::id.eq(envelope_recipient.id)
        ))
            .set(schema::envelope_recipients::dsl::completed.eq(true))
            .execute(c)
    }).await?;

    let task = tasks::sign_envelope::new(envelope, envelope_recipient, field_values, client_meta);
    match celery_app.send_task(task).await {
        Ok(_) => {}
        Err(err) => {
            error!("Failed to submit celery task: {:?}", err);
            return Err(rocket::http::Status::InternalServerError);
        }
    };

    Ok(Json(EnvelopeSignSubmitResp {}))
}
