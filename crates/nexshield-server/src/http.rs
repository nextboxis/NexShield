//! Pure standard library HTTP/1.1 request parsing and response building.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(raw);
        let mut lines = text.lines();

        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_uppercase();
        let full_path = parts.next()?;

        let mut path = full_path.to_string();
        let mut query = HashMap::new();

        if let Some((p, q)) = full_path.split_once('?') {
            path = p.to_string();
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    query.insert(k.to_string(), v.to_string());
                }
            }
        }

        let mut headers = HashMap::new();
        let mut header_end_offset = 0;

        for line in lines {
            if line.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Find boundary between header and body (\r\n\r\n or \n\n)
        for (i, w) in raw.windows(4).enumerate() {
            if w == b"\r\n\r\n" {
                header_end_offset = i + 4;
                break;
            }
        }
        if header_end_offset == 0 {
            for (i, w) in raw.windows(2).enumerate() {
                if w == b"\n\n" {
                    header_end_offset = i + 2;
                    break;
                }
            }
        }

        let body = if header_end_offset > 0 && header_end_offset < raw.len() {
            raw[header_end_offset..].to_vec()
        } else {
            Vec::new()
        };

        Some(Self {
            method,
            path,
            query,
            headers,
            body,
        })
    }

    pub fn body_str(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn new(status: u16, status_text: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            status_text,
            content_type,
            body,
            headers: Vec::new(),
        }
    }

    pub fn ok_json(json: String) -> Self {
        Self::new(200, "OK", "application/json", json.into_bytes())
    }

    pub fn ok_html(html: String) -> Self {
        Self::new(200, "OK", "text/html; charset=utf-8", html.into_bytes())
    }

    pub fn ok_css(css: String) -> Self {
        Self::new(200, "OK", "text/css", css.into_bytes())
    }

    pub fn ok_js(js: String) -> Self {
        Self::new(200, "OK", "application/javascript", js.into_bytes())
    }

    pub fn not_found(msg: &str) -> Self {
        let json = format!(r#"{{"error":"Not Found","message":"{}"}}"#, msg);
        Self::new(404, "Not Found", "application/json", json.into_bytes())
    }

    pub fn bad_request(msg: &str) -> Self {
        let json = format!(r#"{{"error":"Bad Request","message":"{}"}}"#, msg);
        Self::new(400, "Bad Request", "application/json", json.into_bytes())
    }

    pub fn redirect(location: &str) -> Self {
        let mut resp = Self::new(302, "Found", "text/plain", Vec::new());
        resp.headers.push(("Location".to_string(), location.to_string()));
        resp
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nConnection: close\r\n",
            self.status, self.status_text, self.content_type, self.body.len()
        );

        for (k, v) in &self.headers {
            out.push_str(&format!("{}: {}\r\n", k, v));
        }
        out.push_str("\r\n");

        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_request_parsing() {
        let raw = b"POST /api/rag/query HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n{\"query\":\"mitigate SMB EternalBlue\"}";
        let req = HttpRequest::parse(raw).expect("Failed to parse request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/rag/query");
        assert_eq!(req.body_str(), "{\"query\":\"mitigate SMB EternalBlue\"}");
    }
}
