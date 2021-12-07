use chrono::prelude::*;

lazy_static! {
    pub static ref LOG_STATS: std::sync::Mutex<std::collections::HashMap<String, Log>> = {
        std::sync::Mutex::new(std::collections::HashMap::new())
    };
}

#[get("/pingu")]
fn pingu() -> &'static str {
    "NOOT NOOT"
}

#[derive(Serialize, Clone)]
pub struct Log {
    operator: String,
    name: String,
    url: String,
    mmd: u64,
    latest_sth: DateTime<Utc>,
    last_contacted: DateTime<Utc>,
    last_entry: DateTime<Utc>,
    tree_size: u64,
    backlog: u64,
}

impl Log {
    pub fn from_client_log(client_log: &crate::client::CTLog) -> Log {
        Log {
            operator: client_log.operator.clone(),
            name: client_log.name.clone(),
            url: client_log.url.clone(),
            mmd: client_log.mmd.num_seconds().unsigned_abs(),
            latest_sth: Utc.timestamp(0, 0),
            last_contacted: Utc.timestamp(0, 0),
            last_entry: Utc.timestamp(0, 0),
            tree_size: 0,
            backlog: 0
        }
    }

    pub fn update_from_sth(&mut self, sth: &crate::client::SignedTreeHead) {
        self.latest_sth = sth.timestamp.clone();
        self.tree_size = sth.tree_size;
    }

    pub fn update_last_contact(&mut self) {
        self.last_contacted = Utc::now();
    }

    pub fn update_last_entry(&mut self, timestamp: DateTime<Utc>, backlog: u64) {
        self.last_entry = timestamp;
        self.backlog = backlog;
    }
}

#[derive(Serialize)]
struct Logs<> {
    logs: Vec<Log>
}

#[get("/logs")]
fn logs() -> rocket::serde::json::Json<Logs> {
    rocket::serde::json::Json(Logs {
        logs: LOG_STATS.lock().unwrap().values().map(|l| l.clone()).collect()
    })
}

pub async fn main() {
    rocket::build()
        .mount("/", routes![pingu, logs])
        .launch()
        .await
        .unwrap();
}