//! Error codes and the error body (PROTOCOL.md §12).
//!
//! Every error response is `{"error": "<code>", "message": "<human readable>"}`.
//! A `429 rate_limited` response also carries a `Retry-After` header, which is
//! not part of the body and so not modelled here.
//!
//! Servers send only [`ErrorCode`]s. Clients must also accept codes they don't
//! know yet (from a newer server) and then act on the HTTP status alone, so a
//! received body holds an [`AnyErrorCode`].

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

/// The text is not one of the §12 codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownErrorCode;

impl fmt::Display for UnknownErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown error code")
    }
}

impl core::error::Error for UnknownErrorCode {}

impl FromStr for ErrorCode {
    type Err = UnknownErrorCode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == s)
            .ok_or(UnknownErrorCode)
    }
}

/// An error code as received: a known §12 code, or one this build doesn't know.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnyErrorCode {
    Known(ErrorCode),
    Unknown(String),
}

impl AnyErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known(code) => code.as_str(),
            Self::Unknown(code) => code,
        }
    }
}

impl From<ErrorCode> for AnyErrorCode {
    fn from(code: ErrorCode) -> Self {
        Self::Known(code)
    }
}

impl fmt::Display for AnyErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AnyErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AnyErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(match text.parse() {
            Ok(code) => Self::Known(code),
            Err(UnknownErrorCode) => Self::Unknown(text),
        })
    }
}

/// Body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: AnyErrorCode,
    pub message: String,
}

impl ErrorBody {
    pub fn new(error: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }

    /// The code, if this build knows it.
    pub fn code(&self) -> Option<ErrorCode> {
        match self.error {
            AnyErrorCode::Known(code) => Some(code),
            AnyErrorCode::Unknown(_) => None,
        }
    }

    /// HTTP status for a known code. For unknown codes, use the response's
    /// actual status instead.
    pub fn http_status(&self) -> Option<u16> {
        self.code().map(ErrorCode::http_status)
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
        assert_eq!(body.http_status(), Some(403));
    }

    #[test]
    fn body_ignores_unknown_fields() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":"not_found","message":"x","extra":[1,2]}"#).unwrap();
        assert_eq!(body.code(), Some(ErrorCode::NotFound));
    }

    #[test]
    fn strict_code_rejects_unknown_and_wrong_case() {
        assert!(serde_json::from_str::<ErrorCode>(r#""nope""#).is_err());
        assert!(serde_json::from_str::<ErrorCode>(r#""NotFound""#).is_err());
        assert!(serde_json::from_str::<ErrorCode>(r#""not-found""#).is_err());
        assert!("not-found".parse::<ErrorCode>().is_err());
        assert_eq!("not_found".parse::<ErrorCode>(), Ok(ErrorCode::NotFound));
    }

    #[test]
    fn body_keeps_unknown_codes_from_newer_servers() {
        let json = r#"{"error":"new_server_error","message":"Useful explanation"}"#;
        let body: ErrorBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.error, AnyErrorCode::Unknown("new_server_error".into()));
        assert_eq!(body.message, "Useful explanation");
        assert_eq!(body.code(), None);
        assert_eq!(body.http_status(), None);
        assert_eq!(serde_json::to_string(&body).unwrap(), json);
    }

    #[test]
    fn body_rejects_non_string_code() {
        assert!(serde_json::from_str::<ErrorBody>(r#"{"error":7,"message":"x"}"#).is_err());
    }
}
