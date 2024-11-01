use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::env;
use base64::decode;
use dotenv::dotenv;
use actix_cors::Cors;

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
            .route("/films/{id}", web::get().to(get_film_by_id)) // Endpoint baru untuk fetch film by ID
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
