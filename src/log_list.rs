use chrono::prelude::*;

const LOG_LIST_KEY: &'static str = include_str!("google_log_list_key.pem");
const LOG_LIST_URL: &'static str = "https://www.gstatic.com/ct/log_list/v2/log_list.json";
const LOG_LIST_SIG_URL: &'static str = "https://www.gstatic.com/ct/log_list/v2/log_list.sig";

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
struct TemporalInterval {
    start_inclusive: DateTime<Utc>,
    end_exclusive: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct State {
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct FinalTreeHead {
    tree_size: u64,
    sha256_root_hash: String,
}

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
struct Operator {
    name: String,
    email: Vec<String>,
    logs: Vec<Log>,
}

#[derive(Debug, Deserialize)]
struct CTList {
    version: Option<String>,
    operators: Vec<Operator>,
}

pub fn get_logs(client: reqwest::blocking::Client) -> Vec<crate::client::CTLog> {
    info!("Fetching list of CT logs from Google");
    let list = client.get(LOG_LIST_URL)
        .send().expect("Unable to download CT list")
        .bytes().expect("Unable to read CT list");
    let list_obj = serde_json::from_slice::<CTList>(&list)
        .expect("Unable to decode CT list");
    let list_sig = client.get(LOG_LIST_SIG_URL)
        .send().expect("Unable to download CT list signature")
        .bytes().expect("Unable to read CT list signature");

    let pub_key = openssl::pkey::PKey::public_key_from_pem(LOG_LIST_KEY.as_bytes())
        .expect("Unable to decode CT list signing key");
    let mut verifier = openssl::sign::Verifier::new(
        openssl::hash::MessageDigest::sha256(),
        &pub_key
    ).expect("Unable to create CT list verifier");

    let verified = verifier.verify_oneshot(&list_sig, &list)
        .expect("Unable to verify CT list signature");

    if !verified {
        panic!("CT list signature does not verify");
    }

    let mut out = vec![];
    for operator in list_obj.operators {
        for log in operator.logs {
            if log.log_type != LogType::Production {
                continue;
            }
            if let Some(StateType::Usable(_)) = log.state {
                let name = log.description.unwrap_or(log.log_id.clone());
                out.push(crate::client::CTLog {
                    name,
                    id: log.log_id,
                    public_key: openssl::pkey::PKey::public_key_from_der(
                    &base64::decode(log.key).expect("Invalid base64 in key")
                    ).expect("Invalid public key"),
                    url: log.url,
                    mmd: chrono::Duration::seconds(log.mmd as i64),
                })
            }
        }
    }
    out
}