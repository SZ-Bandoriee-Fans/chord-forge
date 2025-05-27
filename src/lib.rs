use axum::{http, response::{self, IntoResponse}, routing::get, Router};
use serde::Serialize;
use tower_service::Service;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_redoc::Redoc;
#[cfg(target_arch = "wasm32")]
use worker::{event, HttpRequest, Env, Context, Result};


mod domain;
mod infra;
mod app;
mod interfaces;

static TRACING_INIT: std::sync::Once = std::sync::Once::new();

fn router() -> Router{
    use utoipa_redoc::Servable;

    let (openapi_router, api) = OpenApiRouter::with_openapi(OpenApiDoc::openapi()).split_for_parts();
    let openapi_router = openapi_router
        .merge(Redoc::with_url("/redoc", api.clone()));

    Router::new()
        .route("/", get(root))
        .merge(openapi_router)
}


#[derive(Serialize, ToSchema)]
struct Metadata {
    version: &'static str,
    description: &'static str,
}
const METADATA: Metadata = Metadata {
    version: clap::crate_version!(),
    description: "This is the backend service for bandoriee-fans.com, running on Cloudflare Workers.",
};


#[derive(utoipa::OpenApi)]
#[openapi(
    paths(root),
    components(
        schemas(Metadata),
    ),
    info(
        title = "bandoriee-fans.com Backend API",
        version = clap::crate_version!(),
        description = "This is the backend service for bandoriee-fans.com, running on Cloudflare Workers.",
    ),
    servers(
        (url = "https://sz.bandoriee-fans.com", description = "prod server"),
        (url = "http://localhost:8787", description = "dev server"),
    ),
)]

struct OpenApiDoc;


struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};

        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "auth_token",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("user_token"))),
            )
        }
    }
}


#[cfg(target_arch = "wasm32")]
#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    _env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    use tracing::info;
    use tracing_subscriber::{fmt::{format::Pretty, time::UtcTime}, layer::SubscriberExt, util::SubscriberInitExt};

    console_error_panic_hook::set_once();
    TRACING_INIT.call_once(|| {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_timer(UtcTime::rfc_3339())
            .with_writer(tracing_web::MakeWebConsoleWriter::new());
        let perf_layer = tracing_web::performance_layer()
            .with_details_from_fields(Pretty::default());
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(perf_layer)
            .init();
        info!("tracing initialized");
    });

    let mut router = router();

    Ok(router.call(req).await?)
}

#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Metadata", body = Metadata),
    ),
)]
pub async fn root() -> response::Response {
    response::Response::builder()
        .status(http::StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&METADATA).unwrap())
        .unwrap()
        .into_response()
}