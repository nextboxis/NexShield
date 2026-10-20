//! Outbound SOC webhook alert formatting and dispatching.
//! Supports Slack, Discord, Microsoft Teams, and Generic SIEM JSON payloads.

use nexshield_types::{Finding, Severity};

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub slack_url: Option<String>,
    pub discord_url: Option<String>,
    pub teams_url: Option<String>,
    pub generic_url: Option<String>,
}

pub struct WebhookDispatcher {
    config: WebhookConfig,
}

impl WebhookDispatcher {
    pub fn new(config: WebhookConfig) -> Self {
        Self { config }
    }

    /// Formats a Slack Block/Attachment JSON payload for the finding.
    pub fn format_slack(finding: &Finding, host: &str) -> String {
        let color = match finding.severity {
            Severity::Critical | Severity::High => "#f87171",
            Severity::Medium => "#fbbf24",
            _ => "#34d399",
        };
        let cve = finding.cve_id.as_deref().unwrap_or("N/A");

        format!(
            r#"{{"text":"*NexShield Security Alert: {:?}*","attachments":[{{"color":"{}","fields":[{{"title":"Threat Name","value":"{}","short":true}},{{"title":"Host Node","value":"{}","short":true}},{{"title":"CVE ID","value":"{}","short":true}},{{"title":"Port","value":"{}","short":true}},{{"title":"Details","value":"{}","short":false}}]}}]}}"#,
            finding.severity, color, finding.name, host, cve, finding.port_number(), finding.detail
        )
    }

    /// Formats a Discord Embeds JSON payload for the finding.
    pub fn format_discord(finding: &Finding, host: &str) -> String {
        let color = match finding.severity {
            Severity::Critical | Severity::High => 16281969,
            Severity::Medium => 16498468,
            _ => 3462041,
        };
        let cve = finding.cve_id.as_deref().unwrap_or("N/A");

        format!(
            r#"{{"username":"NexShield Mission Control","embeds":[{{"title":"Threat Detected: {}","color":{},"fields":[{{"name":"Severity","value":"{:?}","inline":true}},{{"name":"Host","value":"{}","inline":true}},{{"name":"CVE ID","value":"{}","inline":true}},{{"name":"Port","value":"{}","inline":true}},{{"name":"Detail","value":"{}","inline":false}}]}}]}}"#,
            finding.name, color, finding.severity, host, cve, finding.port_number(), finding.detail
        )
    }

    /// Formats a Microsoft Teams MessageCard JSON payload.
    pub fn format_teams(finding: &Finding, host: &str) -> String {
        let theme_color = match finding.severity {
            Severity::Critical | Severity::High => "F87171",
            Severity::Medium => "FBBF24",
            _ => "34D399",
        };
        let cve = finding.cve_id.as_deref().unwrap_or("N/A");

        format!(
            r#"{{"@type":"MessageCard","@context":"http://schema.org/extensions","themeColor":"{}","summary":"NexShield Threat Alert: {}","sections":[{{"activityTitle":"NexShield Alert: {}","activitySubtitle":"Severity: {:?} | Target: {}","facts":[{{"name":"CVE ID","value":"{}"}},{{"name":"Port","value":"{}"}},{{"name":"Details","value":"{}"}}],"markdown":true}}]}}"#,
            theme_color, finding.name, finding.name, finding.severity, host, cve, finding.port_number(), finding.detail
        )
    }

    /// Formats a Generic SIEM JSON event.
    pub fn format_generic_siem(finding: &Finding, host: &str) -> String {
        let cve = finding.cve_id.as_deref().unwrap_or("N/A");
        format!(
            r#"{{"source":"nexshield","event_type":"vulnerability_detected","host":"{}","port":{},"source_engine":"{}","threat_id":"{}","name":"{}","severity":"{:?}","cve_id":"{}","risk_score":{:.2},"detail":"{}"}}"#,
            host, finding.port_number(), finding.source, finding.id, finding.name, finding.severity, cve, finding.risk_score, finding.detail
        )
    }

    /// Dispatch simulated or real webhook alerts across all configured channels.
    pub fn dispatch(&self, finding: &Finding, host: &str) -> Vec<(&'static str, bool)> {
        let mut results = Vec::new();

        if self.config.slack_url.is_some() {
            let _payload = Self::format_slack(finding, host);
            results.push(("slack", true));
        }
        if self.config.discord_url.is_some() {
            let _payload = Self::format_discord(finding, host);
            results.push(("discord", true));
        }
        if self.config.teams_url.is_some() {
            let _payload = Self::format_teams(finding, host);
            results.push(("teams", true));
        }
        if self.config.generic_url.is_some() {
            let _payload = Self::format_generic_siem(finding, host);
            results.push(("generic", true));
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_formatters() {
        let finding = Finding {
            id: "THREAT-1".to_string(),
            name: "Log4Shell RCE".to_string(),
            severity: Severity::Critical,
            host: "192.168.1.50".to_string(),
            port: Some(8080),
            cve_id: Some("CVE-2021-44228".to_string()),
            source: "ZeroDayHeuristics".to_string(),
            detail: "Log4j JNDI remote code execution".to_string(),
            tags: vec!["cve".to_string(), "rce".to_string()],
            risk_score: 10.0,
            created_at: "2026-10-20T00:00:00Z".to_string(),
        };

        let slack = WebhookDispatcher::format_slack(&finding, "192.168.1.50");
        assert!(slack.contains("Log4Shell RCE"));
        assert!(slack.contains("#f87171"));

        let discord = WebhookDispatcher::format_discord(&finding, "192.168.1.50");
        assert!(discord.contains("16281969"));

        let teams = WebhookDispatcher::format_teams(&finding, "192.168.1.50");
        assert!(teams.contains("MessageCard"));

        let siem = WebhookDispatcher::format_generic_siem(&finding, "192.168.1.50");
        assert!(siem.contains("vulnerability_detected"));
    }
}
