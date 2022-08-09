#![allow(incomplete_features)]
#![feature(adt_const_params)]
#![crate_type = "rlib"]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate diesel_derive_enum;
#[macro_use]
extern crate diesel_migrations;
#[macro_use]
extern crate lopdf;

use rocket_sync_db_pools::database;
use celery::prelude::*;
use rocket_sync_db_pools::Poolable;

pub mod csrf;
mod schema;
mod models;
mod pdf;
pub mod tasks;
pub mod views;
mod files;
pub mod oidc;

const FILES_DIR: &'static str = "./files/";

use foreign_types_shared::ForeignType;

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[database("db")]
pub struct DbConn(diesel::PgConnection);

embed_migrations!("./migrations");

pub async fn db_run<
    T: 'static + std::marker::Send,
    F: 'static + FnOnce(&mut diesel::PgConnection) -> diesel::result::QueryResult<T> + std::marker::Send
>(db: &DbConn, func: F) -> Result<T, rocket::http::Status> {
    Ok(match db.run(func).await {
        Ok(r) => r,
        Err(e) => {
            warn!("DB error: {}", e);
            return Err(rocket::http::Status::InternalServerError);
        }
    })
}

#[derive(Debug, Clone)]
pub struct TypedUUIDField<const T: &'static str> {
    pub uuid: uuid::Uuid,
}

impl<const T: &'static str> Default for TypedUUIDField<T> {
    fn default() -> Self {
        Self {
            uuid: uuid::Uuid::new_v4()
        }
    }
}

impl<const T: &'static str> std::fmt::Display for TypedUUIDField<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}_{}", T, self.uuid.to_simple().encode_lower(&mut uuid::Uuid::encode_buffer())))?;
        Ok(())
    }
}

impl<'a, const T: &'static str> rocket::request::FromParam<'a> for TypedUUIDField<T> {
    type Error = &'static str;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        match uuid::Uuid::parse_str(param.strip_prefix(&format!("{}_", T)).unwrap_or(param)) {
            Ok(id) => Ok(TypedUUIDField {
                uuid: id
            }),
            Err(_) => Err("invalid UUID")
        }
    }
}

impl<const T: &'static str> rocket::http::uri::fmt::UriDisplay<rocket::http::uri::fmt::Path> for TypedUUIDField<T> {
    fn fmt(&self, f: &mut rocket::http::uri::fmt::Formatter<rocket::http::uri::fmt::Path>) -> std::fmt::Result {
        f.write_raw(self.to_string())?;
        Ok(())
    }
}
rocket::http::impl_from_uri_param_identity!([rocket::http::uri::fmt::Path] (const T: &'static str) TypedUUIDField<T>);

impl<const T: &'static str> serde::Serialize for TypedUUIDField<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(deserialize_with = "from_base64")]
    files_key: Vec<u8>,
    oidc: OIDCConfig,
    celery: CeleryConfig,
    smtp: SMTPConfig,
    external_uri: rocket::http::uri::Reference<'static>,
    #[serde(default)]
    signing: Option<SigningConfig>,
    nat64_net: Option<ipnet::Ipv6Net>
}

#[derive(Deserialize)]
pub struct OIDCConfig {
    issuer_url: String,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize)]
pub struct SigningConfig {
    hsm_pin: String,
    hsm_provider: Option<String>,
    pkcs11_key_id: String,
    cert: String,
    cert_chain: Vec<String>
}

#[derive(Deserialize)]
pub struct CeleryConfig {
    amqp_url: String,
}

#[derive(Deserialize, Clone)]
pub struct SMTPConfig {
    pub server: String,
    pub port: u16,
    pub use_tls: bool,
    pub auth: Option<SMTPAuth>
}

#[derive(Deserialize, Clone)]
pub struct SMTPAuth {
    pub username: String,
    pub password: String,
}

fn from_base64<'a, D: serde::Deserializer<'a>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    use serde::de::Error;
    use serde::Deserialize;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| Error::custom(err.to_string())))
}

pub type CeleryApp = std::sync::Arc<celery::Celery<AMQPBroker>>;

pub struct App {
    pub rocket: rocket::Rocket<rocket::Build>,
    pub celery_app: CeleryApp,
    pub smtp_conf: SMTPConfig,
    pub external_uri: rocket::http::uri::Reference<'static>,
    pub signing_info: Option<SigningInfo>
}

#[derive(Clone)]
pub struct SigningInfo {
    pub signing_pkey: openssl::pkey::PKey<openssl::pkey::Private>,
    pub signing_cert: openssl::x509::X509,
    pub signing_cert_chain: Vec<openssl::x509::X509>,
}

pub async fn setup() -> App {
    let rocket = rocket::build();
    let figment = rocket.figment();
    let config = figment.extract::<Config>().expect("Unable to read config");

    let signing_info = match config.signing {
        Some(ref s) => {
            let p11_engine = setup_pkcs11_engine(&s.hsm_pin, s.hsm_provider.as_deref()).await;

            info!("Using PKCS#11 key ID {}", s.pkcs11_key_id);
            let engine_key_id = std::ffi::CString::new(s.pkcs11_key_id.clone()).unwrap();
            let pkey = tokio::task::spawn_blocking(move || -> std::io::Result<openssl::pkey::PKey<openssl::pkey::Private>> {
                unsafe {
                    trace!("Loading OpenSSL UI");
                    let ui = cvt_p(openssl_sys::UI_OpenSSL())?;
                    trace!("Loading private key");
                    let priv_key = cvt_p(openssl_sys::ENGINE_load_private_key(
                        **p11_engine.claim(),
                        engine_key_id.as_ptr(),
                        ui,
                        std::ptr::null_mut(),
                    ))?;
                    Ok(openssl::pkey::PKey::from_ptr(priv_key))
                }
            })
            .await.unwrap().expect("Unable to setup pkey");
            let cert_bytes = tokio::fs::read(&s.cert).await.expect("Unable to read signing certificate");
            let cert = openssl::x509::X509::from_pem(&cert_bytes).expect("Unable to parse signing certificate");

            let mut cert_chain = Vec::with_capacity(s.cert_chain.len());

            for c in &s.cert_chain {
                let cert_bytes = tokio::fs::read(c).await.expect("Unable to read signing certificate");
                let chain_cert = openssl::x509::X509::from_pem(&cert_bytes).expect("Unable to parse signing certificate");
                cert_chain.push(chain_cert);
            }

            Some(SigningInfo {
                signing_pkey: pkey,
                signing_cert: cert,
                signing_cert_chain: cert_chain,
            })
        },
        None => None
    };

    let oidc_app = oidc::OIDCApplication::new(
        &config.oidc.issuer_url,
        &config.oidc.client_id,
        &config.oidc.client_secret,
    ).await.expect("Unable to setup OIDC app");

    let celery_app = celery::app!(
        broker = AMQPBroker { config.celery.amqp_url.clone() },
        tasks = [tasks::sign_envelope, tasks::progress_envelope, tasks::request_signature, tasks::send_final],
        task_routes = [],
        prefetch_count = 2,
        acks_late = true,
        task_retry_for_unexpected = true,
        broker_connection_retry = true,
        broker_connection_timeout = 10,
        heartbeat = Some(10),
    ).await.expect("Unable to setup Celery app");

    let db_pool = diesel::PgConnection::pool("db", &rocket).unwrap();
    embedded_migrations::run_with_output(&db_pool.get().unwrap(), &mut std::io::stdout()).unwrap();

    App {
        smtp_conf: config.smtp.clone(),
        external_uri: config.external_uri.clone(),
        rocket: rocket.manage(config).manage(oidc_app),
        celery_app,
        signing_info,
    }
}

struct P11EngineInner(*mut openssl_sys::ENGINE);

/// Holding type with drop for OpenSSL engine references
#[derive(Clone)]
pub struct P11Engine(std::sync::Arc<std::sync::Mutex<P11EngineInner>>);

impl Drop for P11EngineInner {
    fn drop(&mut self) {
        trace!("Dropping PKCS#11 engine");
        unsafe {
            cvt(openssl_sys::ENGINE_free(self.0)).unwrap();
        }
    }
}

// I think engine pointers can be shared between threads, but if it starts crashing, maybe I'm
// wrong and remove this.
unsafe impl Send for P11EngineInner {}

impl P11Engine {
    fn new(engine: *mut openssl_sys::ENGINE) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(P11EngineInner(
            engine,
        ))))
    }

    fn claim(&self) -> std::sync::MutexGuard<'_, P11EngineInner> {
        self.0.lock().unwrap()
    }
}

impl std::ops::Deref for P11EngineInner {
    type Target = *mut openssl_sys::ENGINE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for P11EngineInner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub async fn setup_pkcs11_engine(pin: &str, provider: Option<&str>) -> P11Engine {
    info!("Loading PKCS#11 module");

    let engine_id = std::ffi::CString::new("pkcs11").unwrap();
    let engine_pin_ctrl = std::ffi::CString::new("PIN").unwrap();
    let engine_module_path_ctrl = std::ffi::CString::new("MODULE_PATH").unwrap();
    let engine_pin = std::ffi::CString::new(pin).unwrap();
    let engine_module_path = provider.map(|p| std::ffi::CString::new(p).unwrap());

    let engine = match match tokio::task::spawn_blocking(
        move || -> Result<P11Engine, openssl::error::ErrorStack> {
            unsafe {
                // Something here seems to be blocking, even though we shouldn't be talking to the HSM yet.
                openssl_sys::ENGINE_load_builtin_engines();
                trace!("Getting OpenSSL PKCS#11 engine");
                let engine =
                    P11Engine::new(cvt_p(openssl_sys::ENGINE_by_id(engine_id.as_ptr()))?);
                trace!("Initialising PKCS#11 engine");
                cvt(openssl_sys::ENGINE_init(**engine.claim()))?;
                trace!("Setting engine PIN");
                cvt(openssl_sys::ENGINE_ctrl_cmd_string(
                    **engine.claim(),
                    engine_pin_ctrl.as_ptr(),
                    engine_pin.as_ptr(),
                    1,
                ))?;
                if let Some(module) = engine_module_path {
                    trace!("Setting engine provider");
                    cvt(openssl_sys::ENGINE_ctrl_cmd_string(
                        **engine.claim(),
                        engine_module_path_ctrl.as_ptr(),
                        module.as_ptr(),
                        1,
                    ))?;
                }
                info!("Loaded PKCS#11 engine");
                Ok(engine)
            }
        },
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            error!("Can't setup OpenSSL: {}", e);
            std::process::exit(-1);
        }
    } {
        Ok(e) => e,
        Err(e) => {
            error!("Can't setup OpenSSL: {}", e);
            std::process::exit(-1);
        }
    };
    engine
}
