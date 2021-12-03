#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

mod tree;
mod client;
mod watcher;
mod log_list;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
struct FileStorage {
    root: std::path::PathBuf,
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

fn main() {
    pretty_env_logger::init();

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
        }

        let new_logs = logs.into_iter()
            .filter(|l| !log_watchers.contains_key(&l.id)).collect::<Vec<_>>();

        for new_log in new_logs {
            let c = client.clone();
            let s = storage.clone();
            let key = new_log.id.clone();
            let (sender, receiver) = std::sync::mpsc::channel();
            info!("Added log: {}", new_log.id);
            std::thread::spawn(move || {
                let mut watcher = watcher::CTWatcher::new(c, new_log, s, receiver);
                watcher.run()
            });
            log_watchers.insert(key, LogWatcherHandle {
                cancel: sender
            });
        }

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
