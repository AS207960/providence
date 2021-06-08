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

fn main() {
    pretty_env_logger::init();

    let mut client_headers = reqwest::header::HeaderMap::new();
    client_headers.insert("Accept",  reqwest::header::HeaderValue::from_static("application/json"));
    let client = reqwest::blocking::Client::builder()
        .user_agent(format!("AS207960 Providence ({})", VERSION))
        .default_headers(client_headers)
        .build()
        .unwrap();

    let logs = log_list::get_logs(client.clone());

    let file_root = std::path::Path::new("./data/").to_path_buf();
    std::fs::create_dir_all(&file_root).unwrap();
    let storage = FileStorage {
        root: file_root
    };

    let threads = logs.into_iter().map(|log| {
        let c = client.clone();
        let s = storage.clone();
        std::thread::spawn(move || {
            let mut watcher = watcher::CTWatcher::new(c, log, &s);
            watcher.run()
        })
    }).collect::<Vec<_>>();

    for t in threads {
        t.join().unwrap();
    }
}
