//! nexshield-notifier: Outbound SOC webhook alert engine for NexShield.

pub mod dispatcher;

pub use dispatcher::{WebhookConfig, WebhookDispatcher};
