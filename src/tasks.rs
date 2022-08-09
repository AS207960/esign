use rand::Rng;
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use celery::prelude::*;
use itertools::Itertools;
use diesel::prelude::*;
use crate::{models, schema, views};
use crate::views::{EnvelopeID, RecipientID};

lazy_static::lazy_static! {
    pub static ref CONFIG: std::sync::RwLock<Option<Config>> = std::sync::RwLock::new(None);
    static ref TEMPLATES: tera::Tera = {
        let mut tera = match tera::Tera::new("templates_email/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec!["html.tera"]);
        tera
    };
}

#[rocket::async_trait]
pub trait EmailTransport {
    async fn send(&self, msg: lettre::Message) -> TaskResult<()>;
}

#[rocket::async_trait]
impl EmailTransport for lettre::transport::stub::AsyncStubTransport {
    async fn send(&self, msg: lettre::Message) -> TaskResult<()> {
        match lettre::AsyncTransport::send(self,msg).await {
            Ok(()) => Ok(()),
            Err(err) => Err(celery::error::TaskError::ExpectedError(format!("Unable to send email: {}", err)))
        }
    }
}

#[rocket::async_trait]
impl EmailTransport for lettre::transport::file::AsyncFileTransport<lettre::Tokio1Executor> {
    async fn send(&self, msg: lettre::Message) -> TaskResult<()> {
        match lettre::AsyncTransport::send(self,msg).await {
            Ok(_) => Ok(()),
            Err(err) => Err(celery::error::TaskError::ExpectedError(format!("Unable to save email to file: {}", err)))
        }
    }
}

#[rocket::async_trait]
impl EmailTransport for lettre::transport::smtp::AsyncSmtpTransport<lettre::Tokio1Executor> {
    async fn send(&self, msg: lettre::Message) -> TaskResult<()> {
        match lettre::AsyncTransport::send(self,msg).await {
            Ok(_) => Ok(()),
            Err(err) => Err(celery::error::TaskError::ExpectedError(format!("Unable to send email with SMTP: {}", err)))
        }
    }
}

type EmailTransportType = Box<dyn EmailTransport + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub db: std::sync::Arc<r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::PgConnection>>>,
    pub transport: std::sync::Arc<EmailTransportType>,
    pub celery: std::sync::Arc<crate::CeleryApp>,
    pub external_uri: rocket::http::uri::Reference<'static>,
    pub signing_info: Option<crate::SigningInfo>
}

#[inline]
fn config() -> Config {
    CONFIG.read().unwrap().as_ref().unwrap().clone()
}

pub fn make_recipient_key() -> String {
    base64::encode_config(
        rand::thread_rng()
            .sample_iter(rand::distributions::Standard)
            .take(64)
            .collect::<Vec<u8>>(),
        base64::URL_SAFE_NO_PAD,
    )
}

pub fn hash_slice(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    hasher.finalize().as_slice().into()
}

pub async fn hash_file<P: AsRef<std::path::Path>>(path: P) -> Option<Vec<u8>> {
    let mut hasher = sha2::Sha512::new();
    let mut file = tokio::io::BufReader::new(
        tokio::fs::File::open(std::path::Path::new(crate::FILES_DIR).join(path)).await.ok()?
    );

    let mut buf = [0; 8192];
    while let Ok(size) = file.read(&mut buf[..]).await {
        if size == 0 {
            break;
        }
        hasher.update(&buf[0..size]);
    }

    Some(hasher.finalize().as_slice().into())
}

#[celery::task]
pub async fn sign_envelope(
    envelope: models::Envelope, recipient: models::EnvelopeRecipient,
    fields: Vec<(models::TemplateField, String)>, client_meta: views::ClientMeta,
) -> TaskResult<()> {
    let conf = config();
    let timestamp = chrono::Utc::now();
    let mut envelope = envelope;
    let mut fields = fields;
    let base_path = std::path::Path::new(crate::FILES_DIR);

    let mut base_file = match tokio::fs::File::open(base_path.join(envelope.current_file)).await {
        Ok(f) => f,
        Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to read envelope file: {}", err)))
    };
    let mut base_file_bytes = vec![];
    if let Err(err) = base_file.read_to_end(&mut base_file_bytes).await {
        return Err(celery::error::TaskError::ExpectedError(format!("Unable to read envelope file: {}", err)));
    }

    let mut pdf_doc = match lopdf::Document::load_mem(&base_file_bytes) {
        Ok(d) => crate::pdf::Document::new(d, &base_file_bytes),
        Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to parse envelope PDF: {}", err)))
    };

    fields.sort_by_key(|f| f.0.page);

    for (page_num, fields) in fields.into_iter().group_by(|f| f.0.page).into_iter() {
        let page = match pdf_doc.page(page_num as u32) {
            Ok(p) => p,
            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error updating page {}: {}", page_num, err)))
        };

        match page.setup(|page| {
            for (field, value) in fields {
                match field.field_type {
                    schema::FieldType::Text | schema::FieldType::Checkbox | schema::FieldType::Date => {
                        match page.add_text(&value, field.top_offset, field.left_offset, field.width, field.height) {
                            Ok(()) => {}
                            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error adding text to page {}: {}", page_num, err)))
                        };
                    }
                    schema::FieldType::Signature => {
                        let img_bytes = match base64::decode_config(&value, base64::STANDARD) {
                            Ok(b) => b,
                            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error decoding base64: {}", err)))
                        };
                        match page.add_png_img(&img_bytes, field.top_offset, field.left_offset, field.width, field.height) {
                            Ok(()) => {},
                            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error adding PNG to page {}: {}", page_num, err)))
                        };
                    }
                }
            }
            Ok(())
        }) {
            Ok(r) => r,
            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error updating page {}: {}", page_num, err)))
        }?;
    }

    let pdf_doc_bytes = match pdf_doc.finalise(conf.signing_info.map(|s| crate::pdf::SigningInfo {
        name: Some(recipient.email.clone()),
        contact_info: Some(recipient.email.clone()),
        date: Some(timestamp.clone()),
        reason: None,
        location: Some(format!("{} ({})", client_meta.ip, client_meta.user_agent)),
        keys: s
    })).await  {
        Ok(b) => b,
        Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Error outputting PDF: {}", err)))
    };

    let new_hash = tokio::task::block_in_place(|| {
        hash_slice(&pdf_doc_bytes)
    });

    let new_file_name = format!("{}.pdf", uuid::Uuid::new_v4());
    let mut new_file = match tokio::fs::File::create(base_path.join(&new_file_name)).await {
        Ok(f) => f,
        Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable create envelope file: {}", err)))
    };
    match new_file.write_all(&pdf_doc_bytes).await {
        Ok(f) => f,
        Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable write to envelope file: {}", err)))
    };
    envelope.current_file = new_file_name.clone();

    {
        let db_pool = conf.db.clone();
        let log_entry = models::EnvelopeLog {
            id: uuid::Uuid::new_v4(),
            envelope_id: envelope.id.clone(),
            timestamp: timestamp.naive_utc(),
            recipient_id: recipient.id.clone(),
            entry_type: schema::LogEntryType::Signed,
            ip_address: client_meta.ip.into(),
            user_agent: client_meta.user_agent,
            current_file: new_file_name.clone(),
            current_document_hash: new_hash,
        };
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            c.transaction(|| -> diesel::result::QueryResult<_>{
                diesel::insert_into(schema::envelope_log::dsl::envelope_log)
                    .values(&log_entry)
                    .execute(&c)?;
                diesel::update(schema::envelopes::dsl::envelopes.filter(
                    schema::envelopes::dsl::id.eq(envelope.id)
                ))
                    .set(schema::envelopes::dsl::current_file.eq(new_file_name))
                    .execute(&c)?;
                Ok(())
            }).map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to write log entry: {}", err))
            })
        })
    }?;

    conf.celery.send_task(progress_envelope::new(envelope)).await.map_err(|err| {
        celery::error::TaskError::ExpectedError(format!("Unable to submit task: {}", err))
    })?;

    Ok(())
}

#[celery::task]
pub async fn progress_envelope(envelope: models::Envelope) -> TaskResult<()> {
    let conf = config();
    let envelope_recipient: Option<models::EnvelopeRecipient> = {
        let db_pool = conf.db.clone();
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            schema::envelope_recipients::dsl::envelope_recipients
                .filter(schema::envelope_recipients::dsl::envelope_id.eq(envelope.id))
                .filter(schema::envelope_recipients::dsl::completed.eq(false))
                .order(schema::envelope_recipients::recipient_order.asc())
                .first::<models::EnvelopeRecipient>(&c).optional().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to fetch envelope recipient: {}", err))
            })
        })
    }?;

    match envelope_recipient {
        Some(r) => {
            conf.celery.send_task(request_signature::new(envelope, r)).await.map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to submit task: {}", err))
            })?;
        },
        None => {
            conf.celery.send_task(send_final::new(envelope)).await.map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to submit task: {}", err))
            })?;
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EnvelopeLogEntry {
    id: uuid::Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    recipient_id: uuid::Uuid,
    recipient_email: String,
    entry_type: crate::schema::LogEntryType,
    ip_address: std::net::IpAddr,
    user_agent: String,
    current_document_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct EnvelopeLog {
    envelope_id: uuid::Uuid,
    entries: Vec<EnvelopeLogEntry>
}

async fn make_signing_log(envelope: &models::Envelope, db: std::sync::Arc<r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::PgConnection>>>) -> TaskResult<String> {
    let entries: Vec<(models::EnvelopeLog, models::EnvelopeRecipient)> = {
        let db_pool = db.clone();
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            schema::envelope_log::dsl::envelope_log
                .filter(schema::envelope_log::dsl::envelope_id.eq(envelope.id))
                .order(schema::envelope_log::dsl::timestamp.asc())
                .inner_join(schema::envelope_recipients::dsl::envelope_recipients)
                .get_results::<(models::EnvelopeLog, models::EnvelopeRecipient)>(&c).map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to fetch envelope logs: {}", err))
            })
        })
    }?;

    let log = EnvelopeLog {
        envelope_id: envelope.id.clone(),
        entries: entries.into_iter().map(|(entry, recipient)| {
            EnvelopeLogEntry {
                id: entry.id,
                timestamp: chrono::DateTime::from_utc(entry.timestamp, chrono::Utc),
                recipient_id: entry.recipient_id,
                recipient_email: recipient.email,
                entry_type: entry.entry_type,
                ip_address: entry.ip_address.ip(),
                user_agent: entry.user_agent,
                current_document_hash: hex::encode(entry.current_document_hash)
            }
        }).collect(),
    };

    Ok(serde_json::to_string_pretty(&log).unwrap())
}

#[derive(Serialize)]
struct SigRequestContext {
    signature_url: String,
    template_name: String,
    current_doc_hash: String,
    current_log_hash: String,
}

#[celery::task]
pub async fn request_signature(envelope: models::Envelope, recipient: models::EnvelopeRecipient) -> TaskResult<()> {
    let conf = config();
    let base_path = std::path::Path::new(crate::FILES_DIR);

    let template: models::Template = match {
        let db_pool = conf.db.clone();
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            schema::templates::dsl::templates.find(envelope.template_id).first::<models::Template>(&c).optional().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to fetch template: {}", err))
            })
        })
    }? {
        Some(t) => t,
        None => return Err(celery::error::TaskError::UnexpectedError("Unable to fetch template: does not exist".to_string()))
    };

    let current_log = make_signing_log(&envelope, conf.db.clone()).await?;
    let current_doc = match tokio::fs::read(base_path.join(envelope.current_file)).await {
        Ok(c) => c,
        Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to read document: {}", err)))
    };
    let current_doc_hash = hex::encode(hash_slice(&current_doc));
    let current_log_hash = hex::encode(hash_slice(current_log.as_bytes()));

    let (email_html, email_txt) = {
        let context = match tera::Context::from_serialize(SigRequestContext {
            signature_url: format!(
                "{}/envelope/{}/sign/{}?key={}",
                conf.external_uri,
                EnvelopeID {
                    uuid: envelope.id.clone()
                },
                RecipientID {
                    uuid: recipient.id.clone()
                },
                recipient.key
            ),
            template_name: template.name.clone(),
            current_doc_hash,
            current_log_hash,
        }) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to encode template context: {}", err)))
        };
        let email_html = match TEMPLATES.render("sig_request.html", &context) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to render template: {}", err)))
        };
        let email_txt = match TEMPLATES.render("sig_request.txt", &context) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to render template: {}", err)))
        };
        (email_html, email_txt)
    };

    let m = match lettre::message::Message::builder()
        .from("AS207960 eSignature <esign@as207960.net>".parse().unwrap())
        .reply_to("Glauca Support <hello@glauca.digital>".parse().unwrap())
        .to(lettre::message::Mailbox {
            name: None,
            email: match recipient.email.parse() {
                Ok(m) => m,
                Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to parse email: {}", err)))
            }
        })
        .subject(template.default_subject.unwrap_or(format!("Your signature requested on: {}", template.name)))
        .multipart(lettre::message::MultiPart::mixed()
            .multipart(lettre::message::MultiPart::alternative_plain_html(
                email_txt,
                email_html
            ))
            .singlepart(lettre::message::Attachment::new("document.pdf".to_string()).body(
                current_doc,
                lettre::message::header::ContentType::parse("application/pdf").unwrap()
            ))
            .singlepart(lettre::message::Attachment::new("log.json".to_string()).body(
                current_log,
                lettre::message::header::ContentType::parse("application/json").unwrap()
            ))
        ) {
        Ok(m) => m,
        Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to generate email: {}", err)))
    };

    match conf.transport.send(m).await {
        Ok(_) => {},
        Err(err) => return Err(err)
    }

    Ok(())
}

#[derive(Serialize)]
struct EnvelopeCompleteContext {
    template_name: String,
    doc_hash: String,
    log_hash: String,
}

#[celery::task]
pub async fn send_final(envelope: models::Envelope) -> TaskResult<()> {
    let conf = config();
    let base_path = std::path::Path::new(crate::FILES_DIR);

    let template: models::Template = match {
        let db_pool = conf.db.clone();
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            schema::templates::dsl::templates.find(envelope.template_id).first::<models::Template>(&c).optional().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to fetch template: {}", err))
            })
        })
    }? {
        Some(t) => t,
        None => return Err(celery::error::TaskError::UnexpectedError("Unable to fetch template: does not exist".to_string()))
    };

    let recipients: Vec<models::EnvelopeRecipient> = {
        let db_pool = conf.db.clone();
        tokio::task::block_in_place(move || {
            let c = db_pool.get().map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to get DB pool connection: {}", err))
            })?;
            schema::envelope_recipients::dsl::envelope_recipients
                .filter(schema::envelope_recipients::dsl::envelope_id.eq(envelope.id))
                .order(schema::envelope_recipients::dsl::recipient_order.asc())
                .get_results::<models::EnvelopeRecipient>(&c).map_err(|err| {
                celery::error::TaskError::ExpectedError(format!("Unable to fetch envelope recipients: {}", err))
            })
        })
    }?;

    let log = make_signing_log(&envelope, conf.db.clone()).await?;
    let doc = match tokio::fs::read(base_path.join(envelope.current_file)).await {
        Ok(c) => c,
        Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to read document: {}", err)))
    };
    let doc_hash = hex::encode(hash_slice(&doc));
    let log_hash = hex::encode(hash_slice(log.as_bytes()));

    let (email_html, email_txt) = {
        let context = match tera::Context::from_serialize(EnvelopeCompleteContext {
            template_name: template.name.clone(),
            doc_hash,
            log_hash,
        }) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to encode template context: {}", err)))
        };
        let email_html = match TEMPLATES.render("envelope_complete.html", &context) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to render template: {}", err)))
        };
        let email_txt = match TEMPLATES.render("envelope_complete.txt", &context) {
            Ok(c) => c,
            Err(err) => return Err(celery::error::TaskError::ExpectedError(format!("Unable to render template: {}", err)))
        };
        (email_html, email_txt)
    };

    let mut m_build = lettre::message::Message::builder()
        .from("AS207960 eSignature <esign@as207960.net>".parse().unwrap())
        .reply_to("Glauca Support <hello@glauca.digital>".parse().unwrap())
        .subject(template.default_subject.unwrap_or(format!("Your signature requested on: {}", template.name)));

    for recipient in recipients {
        m_build = m_build.to(lettre::message::Mailbox {
            name: None,
            email: match recipient.email.parse() {
                Ok(m) => m,
                Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to parse email: {}", err)))
            }
        })
    }

    let m = match m_build.multipart(lettre::message::MultiPart::mixed()
            .multipart(lettre::message::MultiPart::alternative_plain_html(
                email_txt,
                email_html
            ))
            .singlepart(lettre::message::Attachment::new("document.pdf".to_string()).body(
                doc,
                lettre::message::header::ContentType::parse("application/pdf").unwrap()
            ))
            .singlepart(lettre::message::Attachment::new("log.json".to_string()).body(
                log,
                lettre::message::header::ContentType::parse("application/json").unwrap()
            ))
        ) {
        Ok(m) => m,
        Err(err) => return Err(celery::error::TaskError::UnexpectedError(format!("Unable to generate email: {}", err)))
    };

    match conf.transport.send(m).await {
        Ok(_) => {},
        Err(err) => return Err(err)
    }

    Ok(())
}
