use crate::{Config};
use hmac::{NewMac, Mac};

type HmacSha512 = hmac::Hmac<sha2::Sha512>;

pub struct FileKey<'a> {
    file_path: &'a str,
    key: &'a [u8],
}

impl<'a> FileKey<'a> {
    pub fn new<>(file_path: &'a str, key: &'a [u8]) -> FileKey<'a> {
        FileKey {
            file_path,
            key,
        }
    }
}

impl ToString for FileKey<'_> {
    fn to_string(&self) -> String {
        let file_path = base64::encode_config(self.file_path.as_bytes(), base64::URL_SAFE_NO_PAD);
        let expiry = (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp().to_string();

        let mut mac = HmacSha512::new_from_slice(&self.key).unwrap();
        let msg = format!("{};{}", file_path, expiry);
        mac.update(msg.as_bytes());

        let code_bytes = base64::encode_config(mac.finalize().into_bytes(), base64::URL_SAFE_NO_PAD);

        format!("{};{}", expiry, code_bytes)
    }
}


#[get("/static/<file..>")]
pub async fn files(file: std::path::PathBuf) -> Option<rocket::fs::NamedFile> {
    rocket::fs::NamedFile::open(std::path::Path::new("static/").join(file)).await.ok()
}

#[get("/files/<file..>?<key>")]
pub async fn authenticated_files(file: std::path::PathBuf, key: &str, config: &rocket::State<Config>) -> Result<Option<rocket::fs::NamedFile>, rocket::http::Status> {
    let mut key_parts = key.split(";").collect::<Vec<_>>();
    if key_parts.len() != 2 {
        return Err(rocket::http::Status::BadRequest);
    }

    let part_2 = key_parts.pop().unwrap();
    let part_1 = key_parts.pop().unwrap();

    let file_path = base64::encode_config(file.to_string_lossy().as_bytes(), base64::URL_SAFE_NO_PAD);
    let expiry = match part_1.parse::<i64>() {
        Ok(c) => match chrono::NaiveDateTime::from_timestamp_opt(c, 0) {
            Some(c) => chrono::DateTime::<chrono::Utc>::from_utc(c, chrono::Utc),
            None => return Err(rocket::http::Status::UnprocessableEntity)
        }
        Err(_) => return Err(rocket::http::Status::UnprocessableEntity)
    };
    let code_bytes = match base64::decode_config(part_2, base64::URL_SAFE_NO_PAD) {
        Ok(c) => c,
        Err(_) => return Err(rocket::http::Status::UnprocessableEntity)
    };

    let mut mac = HmacSha512::new_from_slice(&config.files_key).unwrap();
    let msg = format!("{};{}", file_path, part_1);
    mac.update(msg.as_bytes());
    if let Err(_) = mac.verify(&code_bytes) {
        return Err(rocket::http::Status::Forbidden);
    }

    if expiry < chrono::Utc::now() {
        return Err(rocket::http::Status::Forbidden);
    }

    Ok(rocket::fs::NamedFile::open(std::path::Path::new(crate::FILES_DIR).join(file)).await.ok())
}