use chrono::prelude::*;
use crate::client::CTLog;

const GOOGLE_LOG_LIST_KEY: &'static str = include_str!("google_log_list_key.pem");
const GOOGLE_LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/v2/log_list.json";
const GOOGLE_LOG_LIST_SIG_URL: &'static str = "https://www.gstatic.com/ct/log_list/v2/log_list.sig";
const APPLE_LOG_LIST_URL: &'static str = "https://valid.apple.com/ct/log_list/current_log_list.json";

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum LogType {
    #[serde(rename = "prod")]
    Production,
    #[serde(rename = "test")]
    Testing,
}

impl std::default::Default for LogType {
    fn default() -> Self {
        LogType::Production
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TemporalInterval {
    start_inclusive: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct State {
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FinalTreeHead {
    tree_size: u64,
    sha256_root_hash: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ReadOnlyState {
    #[serde(flatten)]
    state: State,
    final_tree_head: FinalTreeHead,
}

#[derive(Debug, Deserialize)]
enum StateType {
    #[serde(rename = "pending")]
    Pending(State),
    #[serde(rename = "qualified")]
    Qualified(State),
    #[serde(rename = "usable")]
    Usable(State),
    #[serde(rename = "readonly")]
    ReadOnly(ReadOnlyState),
    #[serde(rename = "retired")]
    Retired(State),
    #[serde(rename = "rejected")]
    Rejected(State),
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Log {
    description: Option<String>,
    key: String,
    log_id: String,
    mmd: u64,
    url: String,
    dns: Option<String>,
    #[serde(default)]
    log_type: LogType,
    state: Option<StateType>,
    temporal_interval: Option<TemporalInterval>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Operator {
    name: String,
    email: Vec<String>,
    logs: Vec<Log>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GoogleCTList {
    version: Option<String>,
    operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AppleCTList {
    version: String,
    #[serde(rename = "assetVersion")]
    asset_version: u32,
    operators: Vec<Operator>,
}

pub fn get_logs(client: reqwest::blocking::Client) -> Result<Vec<crate::client::CTLog>, String> {
    info!("Fetching list of CT logs from Google");
    let google_list = match match client.get(GOOGLE_LOG_LIST_URL).send() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to download Google CT list: {}", err));
        }
    }.bytes() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to read Google CT list: {}", err));
        }
    };
    let google_list_obj = match serde_json::from_slice::<GoogleCTList>(&google_list) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to decode Google CT list: {}", err));
        }
    };
    let google_list_sig = match match client.get(GOOGLE_LOG_LIST_SIG_URL).send() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to download Google CT list signature: {}", err));
        }
    }.bytes() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to read Google CT list signature: {}", err));
        }
    };

    let google_pub_key = openssl::pkey::PKey::public_key_from_pem(GOOGLE_LOG_LIST_KEY.as_bytes())
        .expect("Unable to decode CT list signing key");
    let mut verifier = match openssl::sign::Verifier::new(
        openssl::hash::MessageDigest::sha256(),
        &google_pub_key,
    ) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to create Google CT list verifier: {}", err));
        }
    };

    let google_verified = match verifier.verify_oneshot(&google_list_sig, &google_list) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to verify Google CT list signature: {}", err));
        }
    };

    if !google_verified {
        return Err("Google CT list signature does not verify".to_string());
    }

    info!("Fetching list of CT logs from Apple");
    let apple_list = match match client.get(APPLE_LOG_LIST_URL).send() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to download Apple CT list: {}", err));
        }
    }.bytes() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to read Apple CT list: {}", err));
        }
    };
    let apple_list_obj = match serde_json::from_slice::<AppleCTList>(&apple_list) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("unable to decode Apple CT list: {}", err));
        }
    };

    let mut out = std::collections::HashMap::<String, CTLog>::new();
    for operator in google_list_obj.operators.into_iter().chain(apple_list_obj.operators.into_iter()) {
        for log in operator.logs {
            if log.log_type != LogType::Production {
                continue;
            }
            if let Some(temporal_interval) = &log.temporal_interval {
                if temporal_interval.end_exclusive < Utc::now() {
                    continue;
                }
            }
            if let Some(StateType::Usable(_)) = log.state {
                if !out.contains_key(&log.log_id) {
                    let name = log.description.unwrap_or(log.log_id.clone());
                    out.insert(log.log_id.clone(), crate::client::CTLog {
                        operator: operator.name.clone(),
                        name,
                        id: log.log_id,
                        public_key: match openssl::pkey::PKey::public_key_from_der(
                            match &base64::decode(log.key) {
                                Ok(v) => v,
                                Err(err) => {
                                    return Err(format!("invalid base64 encoding: {}", err));
                                }
                            }
                        ) {
                            Ok(v) => v,
                            Err(err) => {
                                return Err(format!("invalid public key: {}", err));
                            }
                        },
                        url: log.url,
                        mmd: chrono::Duration::seconds(log.mmd as i64),
                    });
                }
            }
        }
    }
    Ok(out.into_values().collect())
}