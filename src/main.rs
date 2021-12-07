#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate lazy_static;

use chrono::prelude::*;
use prost::Message;

mod tree;
mod client;
mod watcher;
mod log_list;
mod api;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
struct FileStorage {
    root: std::path::PathBuf,
}

mod proto {
    include!(concat!(env!("OUT_DIR"), "/providence.rs"));
}

fn chrono_to_proto<T: chrono::TimeZone>(
    time: Option<chrono::DateTime<T>>,
) -> Option<prost_types::Timestamp> {
    time.map(|t| prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    })
}

impl watcher::CTLogStorage for FileStorage {
    fn find_save(&self, log_id: &str) -> Result<Option<crate::tree::CompactMerkleTreeSave>, String> {
        let log_id = urlencoding::encode(log_id);
        let mut save_path = self.root.clone();
        save_path.push(format!("{}.json", log_id));

        if save_path.exists() {
            let save_file = match std::fs::File::open(&save_path) {
                Ok(v) => v,
                Err(err) => return Err(err.to_string())
            };
            let save: crate::tree::CompactMerkleTreeSave = match serde_json::from_reader(&save_file) {
                Ok(v) => v,
                Err(err) => return Err(err.to_string())
            };
            Ok(Some(save))
        } else {
            Ok(None)
        }
    }

    fn save_tree(&self, log_id: &str, save: crate::tree::CompactMerkleTreeSave) -> Result<(), String> {
        let log_id = urlencoding::encode(log_id);
        let mut save_path = self.root.clone();
        save_path.push(format!("{}.json", log_id));

        let save_file = match std::fs::File::create(&save_path) {
            Ok(v) => v,
            Err(err) => return Err(err.to_string())
        };
        match serde_json::to_writer(&save_file, &save) {
            Ok(_) => {}
            Err(err) => return Err(err.to_string())
        };
        Ok(())
    }
}

struct LogWatcherHandle {
    cancel: std::sync::mpsc::Sender<()>,
}

pub struct CTEvent {
    entry: client::Entry,
    log: client::CTLog,
}

fn main() {
    pretty_env_logger::init();

    let rt = tokio::runtime::Runtime::new().expect("Unable to create Tokio runtime");

    let mut client_headers = reqwest::header::HeaderMap::new();
    client_headers.insert("Accept", reqwest::header::HeaderValue::from_static("application/json"));
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("AS207960 Providence ({})", VERSION))
        .default_headers(client_headers)
        .build()
        .unwrap();

    let file_root = std::path::Path::new("./data/").to_path_buf();
    std::fs::create_dir_all(&file_root).unwrap();
    let storage = FileStorage {
        root: file_root
    };

    let (event_tx, event_rx) = std::sync::mpsc::sync_channel::<CTEvent>(100);

    std::thread::spawn(move || {
        let mut log_watchers = std::collections::HashMap::<String, LogWatcherHandle>::new();

        loop {
            let logs = match log_list::get_logs(client.clone()) {
                Ok(v) => v,
                Err(err) => {
                    error!("Error getting CT logs: {}", err);
                    std::thread::sleep(std::time::Duration::from_secs(30));
                    continue;
                }
            };

            let found_log_ids = logs.iter()
                .map(|l| l.id.as_str()).collect::<Vec<_>>();
            let removed_logs = log_watchers.keys()
                .filter(|k| !found_log_ids.contains(&k.as_str()))
                .map(|k| k.to_owned()).collect::<Vec<_>>();

            for removed_log in removed_logs {
                info!("Removing log {}", removed_log);
                let handle = log_watchers.get(&removed_log).unwrap();
                handle.cancel.send(()).unwrap();
                log_watchers.remove(&removed_log);
                api::LOG_STATS.lock().unwrap().remove(&removed_log);
            }

            let new_logs = logs.into_iter()
                .filter(|l| !log_watchers.contains_key(&l.id)).collect::<Vec<_>>();

            for new_log in new_logs {
                let c = client.clone();
                let s = storage.clone();
                let key = new_log.id.clone();
                let (sender, receiver) = std::sync::mpsc::channel();
                api::LOG_STATS.lock().unwrap().insert(key.clone(), api::Log::from_client_log(&new_log));
                info!("Added log: {}", new_log.id);
                let evt_tx = event_tx.clone();
                std::thread::spawn(move || {
                    let mut watcher = watcher::CTWatcher::new(
                        c, new_log, s, receiver, evt_tx,
                    );
                    watcher.run()
                });
                log_watchers.insert(key, LogWatcherHandle {
                    cancel: sender
                });
            }

            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });

    info!("Starting RabbitMQ client");
    let mut amqp_conn = amiquip::Connection::insecure_open(&std::env::var("RABBITMQ_URL").expect("No RABBITMQ_URL variable"))
        .expect("Unable to connect to RabbitMQ server");
    let amqp_channel = amqp_conn.open_channel(None).expect("Unable to open RabbitMQ channel");

    std::thread::spawn(move || {
        let pub_exchange = amqp_channel.exchange_declare(
            amiquip::ExchangeType::Fanout,
            "providence_raw",
            amiquip::ExchangeDeclareOptions {
                durable: true,
                ..amiquip::ExchangeDeclareOptions::default()
            },
        ).expect("Unable to declare RabbitMQ exchange");

        for evt in event_rx.iter() {
            if let Some(leaf) = evt.entry.tree_leaf {
                let proto_evt = proto::RawEvent {
                    timestamp: chrono_to_proto(Some(Utc::now())),
                    event: Some(proto::raw_event::Event::LeafEvent(proto::LeafEvent {
                        index: evt.entry.index,
                        url: format!("{}ct/v1/get-entries?start={}&end={}", evt.log.url, evt.entry.index, evt.entry.index),
                        source: Some(proto::CtLog {
                            name: evt.log.name,
                            id: evt.log.id,
                            url: evt.log.url,
                        }),
                        entry: match leaf.leaf {
                            client::MerkleTreeLeafValue::TimestampedEntry(te) => Some(proto::leaf_event::Entry::TimestampedEntry(proto::TimestampedEntry {
                                timestamp: chrono_to_proto(Some(te.timestamp)),
                                extensions: te.extensions.0,
                                entry: Some(match te.entry {
                                    client::LogEntry::X509Entry(asn1) => proto::timestamped_entry::Entry::Asn1Cert(proto::Asn1Cert {
                                        leaf_certificate: asn1.leaf_certificate,
                                        certificate_chain: asn1.certificate_chain,
                                    }),
                                    client::LogEntry::PreCert(pre_cert) => proto::timestamped_entry::Entry::PreCert(proto::PreCert {
                                        issuer_key_hash: pre_cert.issuer_key_hash.to_vec(),
                                        tbs_certificate: pre_cert.tbs_certificate,
                                        leaf_certificate: pre_cert.leaf_certificate,
                                        certificate_chain: pre_cert.certificate_chain,
                                    })
                                }),
                            }))
                        },
                    })),
                };

                let mut buf = Vec::new();
                buf.reserve(proto_evt.encoded_len());
                proto_evt.encode(&mut buf).unwrap();

                pub_exchange.publish(amiquip::Publish {
                    body: &buf,
                    routing_key: "".to_string(),
                    immediate: false,
                    mandatory: false,
                    properties: amiquip::AmqpProperties::default(),
                }).expect("Unable to publish message");
            }
        }
    });

    rt.block_on(async {
        api::main().await;
    });
}
