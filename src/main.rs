use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::env;
use base64::decode;
use dotenv::dotenv;
use actix_cors::Cors;
use sqlx::Row; 

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file");
    let db_pool = PgPool::connect(&database_url).await.expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .wrap(Cors::permissive())
            .app_data(web::Data::new(db_pool.clone()))
            .route("/films", web::get().to(get_films))
            .route("/films", web::post().to(create_film))
            .route("/films/{id}", web::get().to(get_film_by_id)) 
            .route("/total_movie", web::get().to(count_total_movies)) 
            .route("/chartgenre", web::get().to(get_genre_counts)) 
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}