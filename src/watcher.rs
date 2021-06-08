pub trait CTLogStorage {
    fn find_save(&self, log_id: &str) -> Result<Option<crate::tree::CompactMerkleTreeSave>, String>;

    fn save_tree(&self, log_id: &str, save: crate::tree::CompactMerkleTreeSave) -> Result<(), String>;
}

pub struct CTWatcher<'a, S: CTLogStorage> {
    client: reqwest::blocking::Client,
    log: crate::client::CTLog,
    tree: crate::tree::CompactMerkleTree,
    storage: &'a S,
    cancel: std::sync::mpsc::Receiver<()>
}

impl<'a, S: CTLogStorage> CTWatcher<'a, S> {
    pub fn new(client: reqwest::blocking::Client, log: crate::client::CTLog, storage: &'a S, cancel: std::sync::mpsc::Receiver<()>) -> Self {
        CTWatcher {
            client,
            log,
            tree: crate::tree::CompactMerkleTree::new(),
            storage,
            cancel,
        }
    }

    pub fn run(&mut self) {
        let existing_save = match self.storage.find_save(&self.log.id) {
            Ok(v) => v,
            Err(err) => {
                error!("Can't load existing save for '{}', starting from scratch: {}", self.log.name, err);
                None
            }
        };
        if let Some(save) = existing_save {
            self.tree.load(&save);
        }


        let mut sth = loop {
            match crate::client::get_sth(&self.client, &self.log) {
                Ok(sth) => {
                    break sth;
                }
                Err(err) => {
                    error!("Can't fetch initial STH from '{}': {}", self.log.name, err);
                    std::thread::sleep(std::time::Duration::from_secs(15));
                }
            }
        };

        info!("Watching '{}'...", self.log.name);
        'outer: loop {
            match self.cancel.try_recv() {
                Ok(_) => {
                    info!("Watcher for '{}' ending", self.log.name);
                    break 'outer;
                },
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("Receiver disconnected");
                }
            }

            if sth.tree_size != self.tree.tree_size() {
                let tree_size = self.tree.tree_size();
                let entries_iter = crate::client::GetEntries::new(
                    &self.client, &self.log, sth.tree_size, tree_size
                );
                let mut processed_entries: u64 = 0;
                for entry in entries_iter {
                    let entry = match entry {
                        Ok(v) => v,
                        Err(err) => {
                            warn!("Error getting entries from '{}': {}", self.log.name, err);
                            std::thread::sleep(std::time::Duration::from_secs(15));
                            continue;
                        }
                    };
                    processed_entries += 1;
                    match self.tree.append(&entry.leaf_bytes) {
                        Ok(_) => {}
                        Err(err) => {
                            error!("Unable to append new entry from '{}' to tree: {}", self.log.name, err);
                            std::thread::sleep(std::time::Duration::from_secs(15));
                            continue 'outer;
                        }
                    }
                }
                assert_eq!(processed_entries, sth.tree_size - tree_size);
                assert_eq!(sth.tree_size, self.tree.tree_size());
                let mth = match self.tree.root_hash() {
                    Ok(v) => v,
                    Err(err) => {
                        error!("Unable to calculate MTH with new entries from '{}': {}", self.log.name, err);
                        std::thread::sleep(std::time::Duration::from_secs(15));
                        continue 'outer;
                    }
                };

                if mth != sth.sha256_root_hash {
                    error!("MTH not consistent with STH from '{}'", self.log.name);
                    std::thread::sleep(std::time::Duration::from_secs(15));
                    continue;
                }

                match self.storage.save_tree(&self.log.id,self.tree.save()) {
                    Ok(_) => {},
                    Err(err) => {
                        error!("Can't save state for '{}': {}", self.log.name, err);
                    }
                }
            } else {
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
            match crate::client::get_sth(&self.client, &self.log) {
                Ok(new_sth) => {
                    sth = new_sth
                }
                Err(err) => {
                    error!("Can't fetch new STH from '{}': {}", self.log.name, err);
                    std::thread::sleep(std::time::Duration::from_secs(15));
                }
            }
        }
    }
}
