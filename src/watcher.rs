use chrono::prelude::*;

pub trait CTLogStorage {
    fn find_save(&self, log_id: &str) -> Result<Option<crate::tree::CompactMerkleTreeSave>, String>;

    fn save_tree(&self, log_id: &str, save: crate::tree::CompactMerkleTreeSave) -> Result<(), String>;
}

pub struct CTWatcher<S: CTLogStorage> {
    client: reqwest::blocking::Client,
    log: crate::client::CTLog,
    tree: crate::tree::CompactMerkleTree,
    storage: S,
    cancel: std::sync::mpsc::Receiver<()>,
    evt_sender: std::sync::mpsc::SyncSender<crate::CTEvent>,
}

impl<S: 'static + CTLogStorage + std::marker::Send + Clone> CTWatcher<S> {
    pub fn new(
        client: reqwest::blocking::Client, log: crate::client::CTLog, storage: S,
        cancel: std::sync::mpsc::Receiver<()>,
        evt_sender: std::sync::mpsc::SyncSender<crate::CTEvent>
    ) -> Self {
        CTWatcher {
            client,
            log,
            tree: crate::tree::CompactMerkleTree::new(),
            storage,
            cancel,
            evt_sender,
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
        crate::api::LOG_STATS.lock().unwrap().get_mut(&self.log.id).unwrap().update_from_sth(&sth);

        info!("Watching '{}'...", self.log.name);
        let mut last_offset_time = Utc::now();
        'outer: loop {
            match self.cancel.try_recv() {
                Ok(_) => {
                    info!("Watcher for '{}' ending", self.log.name);
                    break 'outer;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    error!("Receiver disconnected");
                    panic!("Receiver disconnected");
                }
            }

            if sth.tree_size > self.tree.tree_size() {
                let tree_size = self.tree.tree_size();

                let difference = sth.tree_size - tree_size;
                let should_emmit = difference < 1000;
                let mut emmit_entries = Vec::with_capacity(if should_emmit {
                    difference as usize
                } else {
                    0
                });
                info!("New STH for '{}'; size {}; backlog {}; emitting: {}", self.log.name, sth.tree_size, difference, should_emmit);

                let (entry_tx, entry_rx) = std::sync::mpsc::sync_channel(100);
                let mut new_tree = self.tree.clone();
                let log_name = self.log.name.clone();
                let log_id = self.log.id.clone();
                let storage = self.storage.clone();
                let new_tree_h = std::thread::spawn(move || {
                    let mut last_save = new_tree.tree_size();
                    loop {
                        let entries: Vec<_> = match entry_rx.recv() {
                            Ok(e) => e,
                            Err(_) => break
                        };
                        match new_tree.extend(&entries) {
                            Ok(_) => {}
                            Err(err) => {
                                error!("Unable to append new entry from '{}' to tree: {}", log_name, err);
                                return None;
                            }
                        }
                        let new_size = new_tree.tree_size();
                        if new_size - last_save > 1000 {
                            match storage.save_tree(&log_id, new_tree.save()) {
                                Ok(_) => {
                                    last_save = new_size;
                                }
                                Err(err) => {
                                    error!("Can't save state for '{}': {}", log_name, err);
                                }
                            }
                        }
                    }
                    Some(new_tree)
                });

                let mut entries_iter = crate::client::GetEntries::new(
                    &self.client, &self.log, sth.tree_size, tree_size, last_offset_time,
                );
                let mut processed_entries: u64 = 0;
                let mut last_update: u64 = 0;
                for entries in &mut entries_iter {
                    let entries = match entries {
                        Ok(v) => v,
                        Err(err) => {
                            warn!("Error getting entries from '{}': {}", self.log.name, err);
                            std::thread::sleep(std::time::Duration::from_secs(15));
                            continue;
                        }
                    };
                    processed_entries += entries.len() as u64;
                    if should_emmit {
                      emmit_entries.extend(entries.iter().cloned());
                    }

                    if processed_entries - last_update > 100 || processed_entries == difference {
                        last_update = processed_entries;
                        if let Some(last_entry) = entries.as_slice().last() {
                            if let Some(entry) = &last_entry.tree_leaf {
                                let crate::client::MerkleTreeLeafValue::TimestampedEntry(t_entry) = &entry.leaf;
                                crate::api::LOG_STATS.lock().unwrap().get_mut(&self.log.id).unwrap()
                                    .update_last_entry(t_entry.timestamp.clone(), difference - processed_entries);
                            }
                        }
                    }

                    match entry_tx.send(entries.into_iter().map(|e| e.leaf_bytes).collect::<Vec<Vec<u8>>>()) {
                        Ok(_) => {}
                        Err(_) => {
                            std::thread::sleep(std::time::Duration::from_secs(15));
                            continue 'outer;
                        }
                    }
                }
                last_offset_time = entries_iter.last_offset_time;
                // If we don't drop the sender here the thread will never exit
                std::mem::drop(entry_tx);
                let mut new_tree = match new_tree_h.join().unwrap() {
                    Some(v) => v,
                    None => {
                        continue 'outer;
                    }
                };
                assert_eq!(processed_entries, difference);
                assert_eq!(sth.tree_size, new_tree.tree_size());
                info!("Up to date on '{}'", self.log.name);
                let mth = match new_tree.root_hash() {
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

                self.tree = new_tree;

                match self.storage.save_tree(&self.log.id, self.tree.save()) {
                    Ok(_) => {}
                    Err(err) => {
                        error!("Can't save state for '{}': {}", self.log.name, err);
                    }
                }

                if should_emmit {
                    for entry in emmit_entries {
                        self.evt_sender.send(crate::CTEvent {
                            entry,
                            log: self.log.clone()
                        }).expect("Unable to send event");
                    }
                } else {
                    std::mem::drop(emmit_entries);
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
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
