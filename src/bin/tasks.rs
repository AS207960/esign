#[macro_use]
extern crate log;

use rocket_sync_db_pools::Poolable;

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let app = as207960_esign::setup().await;
    let db_pool = diesel::PgConnection::pool("db", &app.rocket).unwrap();
    let celery_app = std::sync::Arc::new(app.celery_app);

    let mut smtp_transport_builder =
        lettre::transport::smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(&app.smtp_conf.server)
        .port(app.smtp_conf.port);
    if app.smtp_conf.use_tls {
        smtp_transport_builder = smtp_transport_builder.tls(
            lettre::transport::smtp::client::Tls::Required(
                lettre::transport::smtp::client::TlsParameters::new(app.smtp_conf.server.clone())
                    .expect("Unable to setup SMTP TLS paramaters")
            )
        );
    }
    if let Some(auth) = &app.smtp_conf.auth {
        smtp_transport_builder = smtp_transport_builder.credentials(
            lettre::transport::smtp::authentication::Credentials::new(
                auth.username.clone(), auth.password.clone()
            )
        )
    }

    as207960_esign::tasks::CONFIG.write().unwrap().replace(as207960_esign::tasks::Config {
        db: std::sync::Arc::new(db_pool),
        transport: std::sync::Arc::new(Box::new(smtp_transport_builder.build())),
        celery: celery_app.clone(),
        external_uri: app.external_uri,
        signing_info: app.signing_info,
    });

    info!("AS207960 eSign task runner starting...");

    celery_app.consume().await.unwrap();
}
