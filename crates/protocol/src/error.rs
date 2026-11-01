//! Error codes and the error body (PROTOCOL.md §12).
//!
//! Every error response is `{"error": "<code>", "message": "<human readable>"}`.
//! A `429 rate_limited` response also carries a `Retry-After` header, which is
//! not part of the body and so not modelled here.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Machine-readable error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // 400
    BadRequest,
    InvalidSignature,
    InvalidPow,
    WeakKdf,
    // 401
    Unauthorized,
    SessionExpired,
    // 403
    Forbidden,
    StepUpRequired,
    QuotaExceeded,
    // 404
    NotFound,
    // 409
    Conflict,
    StaleEpoch,
    OwnedSharedVaults,
    // 410
    ResyncRequired,
    // 413
    RecordTooLarge,
    FileTooLarge,
    // 429
    RateLimited,
    // 426
    UnsupportedVersion,
}

impl ErrorCode {
    /// Every code, in the order of the §12 table.
    pub const ALL: [ErrorCode; 18] = [
        ErrorCode::BadRequest,
        ErrorCode::InvalidSignature,
        ErrorCode::InvalidPow,
        ErrorCode::WeakKdf,
        ErrorCode::Unauthorized,
        ErrorCode::SessionExpired,
        ErrorCode::Forbidden,
        ErrorCode::StepUpRequired,
        ErrorCode::QuotaExceeded,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::StaleEpoch,
        ErrorCode::OwnedSharedVaults,
        ErrorCode::ResyncRequired,
        ErrorCode::RecordTooLarge,
        ErrorCode::FileTooLarge,
        ErrorCode::RateLimited,
        ErrorCode::UnsupportedVersion,
    ];

    /// HTTP status this code is sent with.
    pub const fn http_status(self) -> u16 {
        match self {
            Self::BadRequest | Self::InvalidSignature | Self::InvalidPow | Self::WeakKdf => 400,
            Self::Unauthorized | Self::SessionExpired => 401,
            Self::Forbidden | Self::StepUpRequired | Self::QuotaExceeded => 403,
            Self::NotFound => 404,
            Self::Conflict | Self::StaleEpoch | Self::OwnedSharedVaults => 409,
            Self::ResyncRequired => 410,
            Self::RecordTooLarge | Self::FileTooLarge => 413,
            Self::UnsupportedVersion => 426,
            Self::RateLimited => 429,
        }
    }

    /// The wire spelling of the code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidPow => "invalid_pow",
            Self::WeakKdf => "weak_kdf",
            Self::Unauthorized => "unauthorized",
            Self::SessionExpired => "session_expired",
            Self::Forbidden => "forbidden",
            Self::StepUpRequired => "step_up_required",
            Self::QuotaExceeded => "quota_exceeded",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::StaleEpoch => "stale_epoch",
            Self::OwnedSharedVaults => "owned_shared_vaults",
            Self::ResyncRequired => "resync_required",
            Self::RecordTooLarge => "record_too_large",
            Self::FileTooLarge => "file_too_large",
            Self::RateLimited => "rate_limited",
            Self::UnsupportedVersion => "unsupported_version",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(error: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error,
            message: message.into(),
        }
    }

    /// HTTP status to send this body with.
    pub const fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

impl core::error::Error for ErrorBody {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §12 table, transcribed independently of the implementation.
    const SPEC: &[(u16, &[&str])] = &[
        (
            400,
            &[
                "bad_request",
                "invalid_signature",
                "invalid_pow",
                "weak_kdf",
            ],
        ),
        (401, &["unauthorized", "session_expired"]),
        (403, &["forbidden", "step_up_required", "quota_exceeded"]),
        (404, &["not_found"]),
        (409, &["conflict", "stale_epoch", "owned_shared_vaults"]),
        (410, &["resync_required"]),
        (413, &["record_too_large", "file_too_large"]),
        (429, &["rate_limited"]),
        (426, &["unsupported_version"]),
    ];

    #[test]
    fn every_code_maps_to_the_spec_status() {
        let mut seen = 0;
        for &(status, codes) in SPEC {
            for &name in codes {
                let code: ErrorCode =
                    serde_json::from_value(serde_json::Value::String(name.into())).unwrap();
                assert_eq!(code.http_status(), status, "{name}");
                assert_eq!(code.as_str(), name);
                assert_eq!(code.to_string(), name);
                assert_eq!(
                    serde_json::to_value(code).unwrap(),
                    serde_json::Value::String(name.into())
                );
                seen += 1;
            }
        }
        assert_eq!(seen, ErrorCode::ALL.len());
    }

    #[test]
    fn all_lists_each_code_once_and_matches_the_spec() {
        for (i, a) in ErrorCode::ALL.iter().enumerate() {
            for b in &ErrorCode::ALL[i + 1..] {
                assert_ne!(a, b);
            }
            assert!(
                SPEC.iter().any(|(_, names)| names.contains(&a.as_str())),
                "{a} is not in the spec table"
            );
        }
        // Forces this test to be revisited when a variant is added.
        fn _exhaustive(c: ErrorCode) {
            match c {
                ErrorCode::BadRequest
                | ErrorCode::InvalidSignature
                | ErrorCode::InvalidPow
                | ErrorCode::WeakKdf
                | ErrorCode::Unauthorized
                | ErrorCode::SessionExpired
                | ErrorCode::Forbidden
                | ErrorCode::StepUpRequired
                | ErrorCode::QuotaExceeded
                | ErrorCode::NotFound
                | ErrorCode::Conflict
                | ErrorCode::StaleEpoch
                | ErrorCode::OwnedSharedVaults
                | ErrorCode::ResyncRequired
                | ErrorCode::RecordTooLarge
                | ErrorCode::FileTooLarge
                | ErrorCode::RateLimited
                | ErrorCode::UnsupportedVersion => {}
            }
        }
    }

    #[test]
    fn body_round_trip() {
        let body = ErrorBody::new(ErrorCode::StepUpRequired, "log in with your password");
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"error":"step_up_required","message":"log in with your password"}"#
        );
        assert_eq!(serde_json::from_str::<ErrorBody>(&json).unwrap(), body);
        assert_eq!(body.http_status(), 403);
    }

    #[test]
    fn body_ignores_unknown_fields() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":"not_found","message":"x","extra":[1,2]}"#).unwrap();
        assert_eq!(body.error, ErrorCode::NotFound);
    }

    #[test]
    fn rejects_unknown_code_and_wrong_case() {
        assert!(serde_json::from_str::<ErrorBody>(r#"{"error":"nope","message":"x"}"#).is_err());
        assert!(serde_json::from_str::<ErrorCode>(r#""NotFound""#).is_err());
        assert!(serde_json::from_str::<ErrorCode>(r#""not-found""#).is_err());
    }
}
