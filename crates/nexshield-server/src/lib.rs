//! nexshield-server: Pure Rust multithreaded HTTP REST API & Web Dashboard Server.

pub mod http;
pub mod router;
pub mod server;

pub use http::{HttpRequest, HttpResponse};
pub use router::{AppState, Router};
pub use server::HttpServer;
