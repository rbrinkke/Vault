use http::{
    header::{HeaderName, AUTHORIZATION},
    HeaderMap, StatusCode,
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

pub const DEFAULT_ISSUER: &str = "websocket-bus-internal";
pub const DEFAULT_AUDIENCE: &str = "websocket-bus-internal";
const X_SERVICE_NAME: &str = "x-service-name";

#[derive(Debug, Clone)]
pub struct InternalAuthConfig {
    jwt_secret: String,
    issuer: String,
    audience: String,
}

impl InternalAuthConfig {
    pub fn new(
        jwt_secret: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            jwt_secret: jwt_secret.into(),
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }

    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalServiceClaims {
    pub sub: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub org_scope: Option<serde_json::Value>,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub jti: String,
}

impl InternalServiceClaims {
    pub fn new(service_name: &str, permissions: &[&str], issuer: &str, audience: &str) -> Self {
        let now = unix_timestamp();
        Self {
            sub: service_name.to_string(),
            service: Some(service_name.to_string()),
            permissions: permissions.iter().map(|p| (*p).to_string()).collect(),
            org_scope: Some(serde_json::json!("*")),
            exp: now + 300,
            iat: now,
            iss: issuer.to_string(),
            aud: audience.to_string(),
            jti: Uuid::new_v4().to_string(),
        }
    }

    pub fn effective_service(&self) -> &str {
        self.service.as_deref().unwrap_or(&self.sub)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceTokenError {
    pub error: String,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub service: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ValidationRules<'a> {
    pub allowlist: Option<&'a [&'a str]>,
    pub required_permission: Option<&'a str>,
}

impl<'a> ValidationRules<'a> {
    pub const fn new(
        allowlist: Option<&'a [&'a str]>,
        required_permission: Option<&'a str>,
    ) -> Self {
        Self {
            allowlist,
            required_permission,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundAuthHeaders {
    pub authorization: String,
    pub service_name: String,
}

impl OutboundAuthHeaders {
    pub fn as_pairs(&self) -> Vec<(String, String)> {
        let headers = vec![
            (
                AUTHORIZATION.as_str().to_string(),
                self.authorization.clone(),
            ),
            (X_SERVICE_NAME.to_string(), self.service_name.clone()),
        ];
        headers
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InternalAuthError {
    #[error("{error}")]
    Unauthorized { error: String, code: String },
    #[error("{error}")]
    Forbidden { error: String, code: String },
    #[error("{0}")]
    JwtSign(String),
}

impl InternalAuthError {
    pub fn unauthorized(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Unauthorized {
            error: error.into(),
            code: code.into(),
        }
    }

    pub fn forbidden(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Forbidden {
            error: error.into(),
            code: code.into(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized { .. } => StatusCode::UNAUTHORIZED,
            Self::Forbidden { .. } => StatusCode::FORBIDDEN,
            Self::JwtSign(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn response_body(&self) -> ServiceTokenError {
        match self {
            Self::Unauthorized { error, code } | Self::Forbidden { error, code } => {
                ServiceTokenError {
                    error: error.clone(),
                    code: code.clone(),
                }
            }
            Self::JwtSign(error) => ServiceTokenError {
                error: error.clone(),
                code: "INTERNAL_AUTH_SIGN_FAILED".to_string(),
            },
        }
    }
}

pub fn sign_internal_jwt(
    config: &InternalAuthConfig,
    service_name: &str,
    permissions: &[&str],
) -> Result<String, InternalAuthError> {
    let claims = InternalServiceClaims::new(
        service_name,
        permissions,
        config.issuer(),
        config.audience(),
    );

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret().as_bytes()),
    )
    .map_err(|error| InternalAuthError::JwtSign(format!("JWT sign failed: {error}")))
}

pub fn build_outbound_headers(
    config: &InternalAuthConfig,
    service_name: &str,
    permissions: &[&str],
) -> Result<OutboundAuthHeaders, InternalAuthError> {
    Ok(OutboundAuthHeaders {
        authorization: format!(
            "Bearer {}",
            sign_internal_jwt(config, service_name, permissions)?
        ),
        service_name: service_name.to_string(),
    })
}

pub fn validate_internal_request(
    headers: &HeaderMap,
    config: &InternalAuthConfig,
    rules: ValidationRules<'_>,
) -> Result<ServiceIdentity, InternalAuthError> {
    if let Some(auth_header) = header_value(headers, AUTHORIZATION.as_str()) {
        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            InternalAuthError::unauthorized(
                "Invalid Authorization header format. Expected: Bearer <token>",
                "UNAUTHORIZED",
            )
        })?;
        return validate_jwt(token, config, rules);
    }

    Err(InternalAuthError::unauthorized(
        "Missing Authorization bearer token",
        "UNAUTHORIZED",
    ))
}

fn validate_jwt(
    token: &str,
    config: &InternalAuthConfig,
    rules: ValidationRules<'_>,
) -> Result<ServiceIdentity, InternalAuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[config.issuer()]);
    validation.set_audience(&[config.audience()]);

    let decoded = decode::<InternalServiceClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret().as_bytes()),
        &validation,
    )
    .map_err(|_| {
        warn!("Invalid internal service JWT");
        InternalAuthError::unauthorized("Invalid Authorization bearer token", "UNAUTHORIZED")
    })?;

    let service = decoded.claims.effective_service().to_string();
    ensure_allowlisted(&service, rules.allowlist)?;
    ensure_permission(&decoded.claims.permissions, rules.required_permission)?;

    Ok(ServiceIdentity {
        service,
        permissions: decoded.claims.permissions,
    })
}

fn ensure_allowlisted(service: &str, allowlist: Option<&[&str]>) -> Result<(), InternalAuthError> {
    let Some(allowlist) = allowlist else {
        return Ok(());
    };

    if allowlist.iter().any(|allowed| *allowed == service) {
        return Ok(());
    }

    warn!(service = %service, "Service not allowed");
    Err(InternalAuthError::forbidden(
        "Service not allowed",
        "SERVICE_FORBIDDEN",
    ))
}

fn ensure_permission(
    permissions: &[String],
    required_permission: Option<&str>,
) -> Result<(), InternalAuthError> {
    let Some(required_permission) = required_permission else {
        return Ok(());
    };

    if permissions.iter().any(|permission| {
        permission == "*"
            || permission == required_permission
            || permission
                .strip_suffix(":*")
                .map(|prefix| required_permission.starts_with(prefix))
                .unwrap_or(false)
    }) {
        return Ok(());
    }

    Err(InternalAuthError::forbidden(
        format!("Missing required permission: {required_permission}"),
        "SERVICE_FORBIDDEN",
    ))
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let header_name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    headers.get(header_name)?.to_str().ok()
}

fn unix_timestamp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as usize)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn test_config() -> InternalAuthConfig {
        InternalAuthConfig::new(
            "test-only-not-for-production",
            DEFAULT_ISSUER,
            DEFAULT_AUDIENCE,
        )
    }

    #[test]
    fn validates_jwt_with_permission_and_allowlist() {
        let config = test_config();
        let token = sign_internal_jwt(&config, "websocket-bus", &["execute"]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let identity = validate_internal_request(
            &headers,
            &config,
            ValidationRules::new(Some(&["websocket-bus"]), Some("execute")),
        )
        .unwrap();

        assert_eq!(identity.service, "websocket-bus");
    }

    #[test]
    fn rejects_jwt_missing_permission() {
        let config = test_config();
        let token = sign_internal_jwt(&config, "websocket-bus", &["read"]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let error = validate_internal_request(
            &headers,
            &config,
            ValidationRules::new(Some(&["websocket-bus"]), Some("execute")),
        )
        .unwrap_err();

        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(error.response_body().code, "SERVICE_FORBIDDEN");
    }

    #[test]
    fn rejects_missing_bearer_header() {
        let config = test_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(X_SERVICE_NAME),
            HeaderValue::from_static("websocket-bus"),
        );
        let error = validate_internal_request(
            &headers,
            &config,
            ValidationRules::new(Some(&["websocket-bus"]), Some("execute")),
        )
        .unwrap_err();
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn builds_outbound_headers() {
        let config = test_config();
        let headers = build_outbound_headers(&config, "websocket-bus", &["execute"]).unwrap();
        assert!(headers.authorization.starts_with("Bearer "));
        assert_eq!(headers.service_name, "websocket-bus");
        assert_eq!(
            headers.as_pairs(),
            vec![
                (
                    AUTHORIZATION.as_str().to_string(),
                    headers.authorization.clone()
                ),
                (X_SERVICE_NAME.to_string(), "websocket-bus".to_string()),
            ]
        );
    }

    #[test]
    fn rejects_wrong_allowlist_service() {
        let config = test_config();
        let token = sign_internal_jwt(&config, "notifications-mcp", &["read"]).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let error = validate_internal_request(
            &headers,
            &config,
            ValidationRules::new(Some(&["action-executor"]), Some("read")),
        )
        .unwrap_err();
        assert_eq!(error.status_code(), StatusCode::FORBIDDEN);
    }
}
