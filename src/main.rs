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
use sqlx::Row; 


//--------------------------------------LOGIN RREGISTER------------------------------------------------------------------

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



//---------------------------------------FILM-------------------------------------------------------
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
#[derive(Serialize)]
struct TotalMoviesResponse {
    total: i64,
    change_percentage: f64,
    change_from_last_year: i64,
}
#[derive(Serialize)]
struct GenreData {
    genre: String,
    count: i64,
}

async fn get_genre_counts(db_pool: web::Data<PgPool>) -> impl Responder {
    // Ambil semua film dan genre mereka dari database
    let query = r#"
        SELECT genre
        FROM data_film
    "#;

    match sqlx::query(query)
        .fetch_all(&**db_pool)
        .await {
        Ok(rows) => {
            let mut genre_map: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

            for row in rows {
                let genre_string: String = row.get("genre");
                // Pisahkan genre yang terpisah oleh koma
                let genres: Vec<&str> = genre_string.split(',').map(|s| s.trim()).collect();

                // Hitung setiap genre
                for genre in genres {
                    *genre_map.entry(genre.to_string()).or_insert(0) += 1;
                }
            }

            // Ubah genre_map ke dalam format GenreData
            let genre_counts: Vec<GenreData> = genre_map.into_iter()
                .map(|(genre, count)| GenreData { genre, count })
                .collect();

            HttpResponse::Ok().json(genre_counts)
        }
        Err(err) => {
            eprintln!("Error fetching genres: {}", err);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn count_total_movies(db_pool: web::Data<PgPool>) -> impl Responder {
    let total_query = "SELECT COUNT(*) FROM data_film";

    // Mengambil total film
    let total_result = sqlx::query(total_query)
        .fetch_one(&**db_pool)
        .await;

    match total_result {
        Ok(total_row) => {
            let total: i64 = total_row.get(0);

            // Menghasilkan respons tanpa data tahun lalu
            let response = TotalMoviesResponse {
                total,
                change_percentage: 0.0, // Anda dapat menyetel ini sesuai kebutuhan
                change_from_last_year: 0, // Anda dapat menyetel ini sesuai kebutuhan
            };

            HttpResponse::Ok().json(response)
        }
        Err(_) => {
            HttpResponse::InternalServerError().finish()
        }
    }
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

//----------------------------------LUPA PASSWORD & RESET PASSWORD-----------------------------------------------
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


//-------------------------------------------ULO REPORT-----------------------------------------------------------
async fn report_register(db_pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    // Execute the count query
    let result = sqlx::query_scalar!("SELECT COUNT(*) FROM user_ulo")
        .fetch_one(&**db_pool)
        .await;

    // Check the result and return the count
    match result {
        Ok(Some(count)) => Ok(HttpResponse::Ok().json(format!("Total registered users: {}", count))),
        Ok(None) => Ok(HttpResponse::Ok().json("Total registered users: 0")),
        Err(e) => {
            eprintln!("Error retrieving user count: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to retrieve user count"))
        }
    }
}

async fn report_movie(db_pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    // Execute the count query
    let result = sqlx::query_scalar!("SELECT COUNT(*) FROM data_film")
        .fetch_one(&**db_pool)
        .await;

    // Check the result and return the count
    match result {
        Ok(Some(count)) => Ok(HttpResponse::Ok().json(format!("Total movie: {}", count))),
        Ok(None) => Ok(HttpResponse::Ok().json("Total movie: 0")),
        Err(e) => {
            eprintln!("Error retrieving movie count: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to retrieve user count"))
        }
    }
}

#[derive(Serialize)]
struct GenreCount {
    genre: Option<String>,
    count: Option<i64>,
}

async fn report_genre(db_pool: web::Data<PgPool>) -> Result<HttpResponse, Error> {
    // Execute the query to count films by genre
    let results = sqlx::query_as!(
        GenreCount,
        r#"SELECT genre, COUNT(*) as count FROM data_film GROUP BY genre"#
    )
    .fetch_all(&**db_pool)
    .await;

    match results {
        Ok(genres) => {
            // Format the response as "horror: 30, action: 10"
            let response = genres
                .into_iter()
                .filter_map(|g| {
                    if let Some(genre) = g.genre {
                        // Use unwrap_or_default to handle Option<i64>
                        let count = g.count.unwrap_or(0); // Default to 0 if None
                        Some(format!("{}: {}", genre, count))
                    } else {
                        None
                    }
                })
                .collect::<Vec<String>>()
                .join(", ");

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            eprintln!("Error retrieving genre counts: {}", e);
            Ok(HttpResponse::InternalServerError().json("Failed to retrieve genre counts"))
        }
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
            .route("/films/{id}", web::get().to(get_film_by_id)) 
            .route("/total_movie", web::get().to(count_total_movies)) 
            .route("/chartgenre", web::get().to(get_genre_counts)) 

            .route("/send_otp", web::post().to(send_otp))
            .route("/verify_otp", web::post().to(verify_otp))
            .route("/reset_password", web::post().to(reset_password))

            .route("/report/register", web::get().to(report_register))
            .route("/report/movie", web::get().to(report_movie))
            .route("/report/genre", web::get().to(report_genre))

    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}