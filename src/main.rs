use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, Error};
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header;
use lettre::transport::smtp::authentication::Credentials;
use rand::Rng;
use base64::decode;
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::env;


//LOGIN

#[derive(Serialize, Deserialize)]
struct RegisterData {
    username: String,
    email: String,
    password: String,
    nomor_telepon: String,
}

#[derive(Serialize, Deserialize)]
struct LoginData {
    email: String,
    password: String,
}

// Function to register a user
async fn register_user(data: web::Json<RegisterData>, db_pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    let user = data.into_inner();

    let result = sqlx::query!(
        "INSERT INTO user_ulo (username, email, password, nomor_telepon) VALUES ($1, $2, $3, $4)",
        user.username,
        user.email,
        user.password,
        user.nomor_telepon
    )
    .execute(&**db_pool)
    .await;

    match result {
        Ok(_) => Ok(HttpResponse::Created().json("User registered successfully")),
        Err(e) => {
            eprintln!("Error registering user: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to register user"))
        }
    }
}

// Function to log in a user
async fn login_user(data: web::Json<LoginData>, db_pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    let login_data = data.into_inner();

    // Attempt to fetch user data
    match sqlx::query!(
        "SELECT * FROM user_ulo WHERE email = $1 AND password = $2",
        login_data.email,
        login_data.password
    )
    .fetch_all(&**db_pool)
    .await 
    {
        Ok(rows) => {
            if rows.is_empty() {
                Ok(HttpResponse::Unauthorized().json("Invalid email or password"))
            } else {
                Ok(HttpResponse::Ok().json("Login successful"))
            }
        }
        Err(e) => {
            eprintln!("Database query error: {}", e);
            Ok(HttpResponse::InternalServerError().json("Internal Server Error"))
        }
    }
}



//FILM
#[derive(Serialize, Deserialize)]
struct DataFilm {
    id: i32,
    nama: String,
    thumbnail: Option<String>,
    durasi: Option<String>,
    resolusi: Option<String>,
    tipe_audio: Option<String>,
    rating_usia: Option<String>,
    keterangan_rating: Option<String>,
    pemeran: Option<String>,
    genre: Option<String>,
    film_ini: Option<String>,
    sinopsis: Option<String>,
    sutradara: Option<String>,
    penulis: Option<String>,
}

async fn get_films(db_pool: web::Data<PgPool>) -> impl Responder {
    let films = sqlx::query_as!(
        DataFilm,
        "SELECT id, nama, encode(thumbnail, 'base64') as thumbnail, durasi, resolusi, tipe_audio, rating_usia, keterangan_rating, pemeran, genre, film_ini, sinopsis, sutradara, penulis FROM data_film"
    )
    .fetch_all(&**db_pool)
    .await;

    match films {
        Ok(films) => HttpResponse::Ok().json(films),
        Err(_) => HttpResponse::InternalServerError().body("Error retrieving films"),
    }
}

async fn get_film_by_id(id: web::Path<i32>, db_pool: web::Data<PgPool>) -> impl Responder {
    let film = sqlx::query_as!(
        DataFilm,
        "SELECT id, nama, encode(thumbnail, 'base64') as thumbnail, durasi, resolusi, tipe_audio, rating_usia, keterangan_rating, pemeran, genre, film_ini, sinopsis, sutradara, penulis FROM data_film WHERE id = $1",
        *id
    )
    .fetch_optional(&**db_pool)
    .await;

    match film {
        Ok(Some(film)) => HttpResponse::Ok().json(film),
        Ok(None) => HttpResponse::NotFound().body("Film not found"),
        Err(_) => HttpResponse::InternalServerError().body("Error retrieving film"),
    }
}

async fn create_film(film: web::Json<DataFilm>, db_pool: web::Data<PgPool>) -> impl Responder {
    let thumbnail_bytes = match &film.thumbnail {
        Some(thumbnail_base64) => {
            let base64_data = if thumbnail_base64.starts_with("data:image/jpeg;base64,") {
                thumbnail_base64.replace("data:image/jpeg;base64,", "")
            } else if thumbnail_base64.starts_with("data:image/png;base64,") {
                thumbnail_base64.replace("data:image/png;base64,", "")
            } else {
                return HttpResponse::BadRequest().body("Unsupported image format");
            };

            match decode(base64_data) {
                Ok(bytes) => Some(bytes),
                Err(_) => return HttpResponse::BadRequest().body("Invalid base64 thumbnail"),
            }
        }
        None => None,
    };

    let result = sqlx::query!(
        "INSERT INTO data_film (nama, thumbnail, durasi, resolusi, tipe_audio, rating_usia, keterangan_rating, pemeran, genre, film_ini, sinopsis, sutradara, penulis) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
        film.nama,
        thumbnail_bytes.as_ref(),
        film.durasi,
        film.resolusi,
        film.tipe_audio,
        film.rating_usia,
        film.keterangan_rating,
        film.pemeran,
        film.genre,
        film.film_ini,
        film.sinopsis,
        film.sutradara,
        film.penulis,
    )
    .fetch_one(&**db_pool)
    .await;

    match result {
        Ok(record) => HttpResponse::Created().json(record.id),
        Err(_) => HttpResponse::InternalServerError().body("Error creating film"),
    }
}

//LUPA PASSWORD & RESET PASSWORD
#[derive(Serialize, Deserialize)]
struct OtpRequestData {
    email: String,
}

#[derive(Serialize, Deserialize)]
struct OtpVerificationData {
    email: String,
    otp: String,
}

#[derive(Serialize, Deserialize)]
struct PasswordResetData {
    email: String,
    new_password: String,
}

// Function to send OTP
async fn send_otp(
    data: web::Json<OtpRequestData>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
    let email = data.email.clone();
    let otp: String = rand::thread_rng().gen_range(1000..9999).to_string();

    let result = sqlx::query!("UPDATE user_ulo SET otp = $1 WHERE email = $2", otp, email)
        .execute(&**db_pool)
        .await;

    if result.is_err() {
        return Ok(HttpResponse::InternalServerError().json("Failed to update OTP"));
    }

    dotenv().ok();
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

    let email_message = Message::builder()
        .from(smtp_username.parse().unwrap())
        .to(email.parse().unwrap())
        .subject("Your OTP Code")
        .header(header::ContentType::TEXT_PLAIN)
        .body(format!("Your OTP code is: {}", otp))
        .unwrap();

    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::relay(&env::var("SMTP_SERVER").unwrap())
        .unwrap()
        .credentials(creds)
        .build();

    match mailer.send(&email_message) {
        Ok(_) => Ok(HttpResponse::Ok().json("OTP sent successfully")),
        Err(_) => Ok(HttpResponse::InternalServerError().json("Failed to send OTP email")),
    }
}

// Function to verify OTP
async fn verify_otp(
    data: web::Json<OtpVerificationData>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
    let email = &data.email;
    let otp = &data.otp;

    let rows = sqlx::query!(
        "SELECT * FROM user_ulo WHERE email = $1 AND otp = $2",
        email,
        otp
    )
    .fetch_optional(&**db_pool)
    .await;

    match rows {
        Ok(Some(_)) => Ok(HttpResponse::Ok().json("OTP verified successfully")),
        Ok(None) => Ok(HttpResponse::Unauthorized().json("Invalid OTP")),
        Err(_) => Ok(HttpResponse::InternalServerError().json("Database error")),
    }
}

// Function to reset password
async fn reset_password(
    data: web::Json<PasswordResetData>,
    db_pool: web::Data<PgPool>,
) -> Result<HttpResponse, Error> {
    let email = &data.email;
    let new_password = &data.new_password;

    let result = sqlx::query!(
        "UPDATE user_ulo SET password = $1, otp = NULL WHERE email = $2",
        new_password,
        email
    )
    .execute(&**db_pool)
    .await;

    match result {
        Ok(_) => Ok(HttpResponse::Ok().json("Password reset successfully")),
        Err(_) => Ok(HttpResponse::InternalServerError().json("Failed to reset password")),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");
    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(db_pool.clone()))
            .route("/register", web::post().to(register_user))
            .route("/login", web::post().to(login_user))


            .route("/films", web::get().to(get_films))
            .route("/films", web::post().to(create_film))
            .route("/films/{id}", web::get().to(get_film_by_id)) // Endpoint baru untuk fetch film by ID

            .route("/send_otp", web::post().to(send_otp))
            .route("/verify_otp", web::post().to(verify_otp))
            .route("/reset_password", web::post().to(reset_password))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
