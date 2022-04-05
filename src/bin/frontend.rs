#[macro_use]
extern crate log;

#[tokio::main]
async fn main() -> Result<(), rocket::Error> {
    pretty_env_logger::init();

    let app = as207960_esign::setup().await;

    info!("AS207960 eSign frontend starting...");

    app.rocket
        .attach(as207960_esign::DbConn::fairing())
        .attach(as207960_esign::csrf::CSRFFairing)
        .attach(rocket_dyn_templates::Template::fairing())
        .manage(app.celery_app)
        .mount("/", rocket::routes![
            as207960_esign::oidc::oidc_redirect,
            as207960_esign::views::templates,
            as207960_esign::views::templates_no_auth,
            as207960_esign::views::template,
            as207960_esign::views::template_no_auth,
            as207960_esign::views::template_submit,
            as207960_esign::views::template_submit_no_auth,
            as207960_esign::views::envelopes,
            as207960_esign::views::envelopes_no_auth,
            as207960_esign::views::envelope,
            as207960_esign::views::envelope_no_auth,
            as207960_esign::views::envelope_sign,
            as207960_esign::views::envelope_sign_submit,
            as207960_esign::views::files,
            as207960_esign::views::authenticated_files
        ])
        .launch()
        .await
}