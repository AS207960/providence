use chrono::prelude::*;
use std::convert::TryFrom;

#[derive(Debug)]
pub struct CTLog {
    pub name: String,
    pub id: String,
    pub public_key: openssl::pkey::PKey<openssl::pkey::Public>,
    pub url: String,
    pub mmd: chrono::Duration,
}

#[derive(Debug, Deserialize)]
struct SignedTreeHeadJSON {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

#[derive(Debug, Deserialize)]
struct EntryJSON {
    leaf_input: String,
    extra_data: String,
}

#[derive(Debug, Deserialize)]
struct EntriesJSON {
    entries: Vec<EntryJSON>,
}

#[derive(Debug, Deserialize)]
struct ConsistencyJSON {
    consistency: Vec<String>,
}

#[derive(Debug)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub timestamp: DateTime<Utc>,
    pub sha256_root_hash: [u8; 32],
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((p as *const T) as *const u8, std::mem::size_of::<T>())
    }
}

fn u8_slice_as_any<T: Sized>(p: &[u8]) -> Option<&T> {
    unsafe {
        let len_t = std::mem::size_of::<T>();
        if len_t < p.len() {
            return None;
        }
        let ref t = *(p.as_ptr() as *const T);
        Some(t)
    }
}

// fn u8_slice_as_any_mut<T: Sized>(p: &mut [u8]) -> Option<&mut T> {
//     unsafe {
//         let len_t = std::mem::size_of::<T>();
//         if len_t < p.len() {
//             return None;
//         }
//         let ref mut t = *(p.as_ptr() as *mut T);
//         Some(t)
//     }
// }

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
enum HashAlgorithm {
    None = 0,
    MD5 = 1,
    SHA = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
}

impl From<&HashAlgorithm> for openssl::hash::MessageDigest {
    fn from(from: &HashAlgorithm) -> openssl::hash::MessageDigest {
        match from {
            HashAlgorithm::None => openssl::hash::MessageDigest::null(),
            HashAlgorithm::MD5 => openssl::hash::MessageDigest::md5(),
            HashAlgorithm::SHA => openssl::hash::MessageDigest::sha1(),
            HashAlgorithm::SHA224 => openssl::hash::MessageDigest::sha224(),
            HashAlgorithm::SHA256 => openssl::hash::MessageDigest::sha256(),
            HashAlgorithm::SHA384 => openssl::hash::MessageDigest::sha384(),
            HashAlgorithm::SHA512 => openssl::hash::MessageDigest::sha512(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct DigitallySignedHeader {
    algorithm: SignatureAndHashAlgorithm,
    signature_length: simple_endian::u16be,
}

#[derive(Debug, Clone)]
struct DigitallySigned {
    algorithm: SignatureAndHashAlgorithm,
    signature: Vec<u8>,
}

impl DigitallySigned {
    fn from_u8(p: &[u8]) -> Option<Self> {
        let h_len = std::mem::size_of::<DigitallySignedHeader>();
        if p.len() < h_len {
            return None;
        };
        let header = u8_slice_as_any::<DigitallySignedHeader>(&p[..h_len])?;
        let remainder = &p[h_len..];
        let sig_len = { header.signature_length }.to_native();
        if remainder.len() != sig_len as usize {
            return None;
        };
        let signature = remainder.to_vec();
        let digitally_signed = Self {
            algorithm: header.algorithm.clone(),
            signature,
        };
        Some(digitally_signed)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Version {
    V1 = 0
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
#[allow(dead_code)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct TreeHeadSignature {
    version: Version,
    signature_type: SignatureType,
    timestamp: simple_endian::u64be,
    tree_size: simple_endian::u64be,
    sha256_root_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ASN1Cert(pub Vec<u8>);

impl ASN1Cert {
    fn from_bytes(p: &mut Vec<u8>) -> Option<Self> {
        if p.len() < 3 {
            return None;
        };
        let mut header_bytes = p.drain(..3).collect::<Vec<u8>>();
        let mut header_bytes_u32 = vec![0];
        header_bytes_u32.append(&mut header_bytes);
        let len = u8_slice_as_any::<simple_endian::u32be>(&header_bytes_u32)?.to_native() as usize;

        if p.len() < len {
            return None;
        };

        let data = p.drain(..len).collect::<Vec<u8>>();
        Some(Self(data))
    }
}

#[derive(Debug, Clone)]
pub struct CTExtensions(pub Vec<u8>);

impl CTExtensions {
    fn from_bytes(p: &mut Vec<u8>) -> Option<Self> {
        if p.len() < 2 {
            return None;
        };
        let header_bytes = p.drain(..2).collect::<Vec<u8>>();
        let len = u8_slice_as_any::<simple_endian::u16be>(&header_bytes)?.to_native() as usize;

        if p.len() < len {
            return None;
        };

        let data = p.drain(..len).collect::<Vec<u8>>();
        Some(Self(data))
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct PreCertHeader {
    issuer_key_hash: [u8; 32],
    tbs_certificate_len: [u8; 3],
}

#[derive(Debug, Clone)]
pub struct PreCert {
    pub issuer_key_hash: [u8; 32],
    pub tbs_certificate: Vec<u8>,
}

impl PreCert {
    fn from_bytes(p: &mut Vec<u8>) -> Option<Self> {
        let h_len = std::mem::size_of::<PreCertHeader>();
        if p.len() < h_len {
            return None;
        };
        let header_bytes = p.drain(..h_len).collect::<Vec<u8>>();
        let header = u8_slice_as_any::<PreCertHeader>(&header_bytes)?;

        let mut len_bytes_u32 = vec![0];
        len_bytes_u32.extend(header.tbs_certificate_len);
        let tbs_certificate_len = u8_slice_as_any::<simple_endian::u32be>(&len_bytes_u32)?.to_native() as usize;
        if p.len() < tbs_certificate_len {
            return None;
        };

        let data = p.drain(..tbs_certificate_len).collect::<Vec<u8>>();

        Some(Self {
            issuer_key_hash: header.issuer_key_hash,
            tbs_certificate: data,
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
#[allow(dead_code)]
enum LogEntryType {
    X509Entry = 0,
    PreCertEntry = 1,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct TimestampedEntryHeader {
    timestamp: simple_endian::u64be,
    entry_type: LogEntryType,
}

#[derive(Clone, Debug)]
pub enum LogEntry {
    X509Entry(ASN1Cert),
    PreCert(PreCert),
}

#[derive(Clone, Debug)]
pub struct TimestampedEntry {
    pub timestamp: DateTime<Utc>,
    pub entry: LogEntry,
    pub extensions: CTExtensions,
}

impl TimestampedEntry {
    fn from_bytes(p: &mut Vec<u8>) -> Option<Self> {
        let h_len = std::mem::size_of::<TimestampedEntryHeader>();
        if p.len() < h_len {
            return None;
        };
        let header_bytes = p.drain(..h_len).collect::<Vec<u8>>();
        let header = u8_slice_as_any::<TimestampedEntryHeader>(&header_bytes)?;

        let entry = match header.entry_type {
            LogEntryType::X509Entry => {
                let cert = ASN1Cert::from_bytes(p)?;
                LogEntry::X509Entry(cert)
            }
            LogEntryType::PreCertEntry => {
                let pre_cert = PreCert::from_bytes(p)?;
                LogEntry::PreCert(pre_cert)
            }
        };

        let extensions = CTExtensions::from_bytes(p)?;

        Some(Self {
            timestamp: Utc.timestamp_millis({ header.timestamp }.to_native() as i64),
            entry,
            extensions,
        })
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
#[allow(dead_code)]
enum MerkleLeafType {
    TimestampedEntry = 0
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct MerkleTreeLeafHeader {
    version: Version,
    leaf_type: MerkleLeafType,
}

#[derive(Clone, Debug)]
pub enum MerkleTreeLeafValue {
    TimestampedEntry(TimestampedEntry)
}

#[derive(Clone, Debug)]
pub struct MerkleTreeLeaf {
    pub version: Version,
    pub leaf: MerkleTreeLeafValue,
}

impl MerkleTreeLeaf {
    fn from_bytes(p: &mut Vec<u8>) -> Option<Self> {
        let h_len = std::mem::size_of::<MerkleTreeLeafHeader>();
        if p.len() < h_len {
            return None;
        };
        let header_bytes = p.drain(..h_len).collect::<Vec<u8>>();
        let header = u8_slice_as_any::<MerkleTreeLeafHeader>(&header_bytes)?;

        if header.version != Version::V1 {
            return None;
        }

        let leaf = match header.leaf_type {
            MerkleLeafType::TimestampedEntry => {
                let entry = TimestampedEntry::from_bytes(p)?;
                MerkleTreeLeafValue::TimestampedEntry(entry)
            }
        };

        let digitally_signed = Self {
            version: header.version,
            leaf,
        };
        Some(digitally_signed)
    }
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub index: u64,
    pub tree_leaf: Option<MerkleTreeLeaf>,
    pub leaf_bytes: Vec<u8>,
    pub extra_data: Vec<u8>,
}

pub struct GetEntries<'a> {
    client: &'a reqwest::blocking::Client,
    log: &'a CTLog,
    size: u64,
    start_from: u64,
    offset: u64,
    last_offset: u64,
    pub last_offset_time: DateTime<Utc>
}

impl<'a> GetEntries<'a> {
    pub fn new(client: &'a reqwest::blocking::Client, log: &'a CTLog, size: u64, offset: u64, last_offset_time: DateTime<Utc>) -> Self {
        GetEntries {
            client,
            log,
            size,
            start_from: offset,
            offset: 0,
            last_offset: 0,
            last_offset_time,
        }
    }

    fn decode_entry(&self, entry: &EntryJSON, index: u64) -> Result<Entry, String> {
        let merkle_leaf_bytes = match base64::decode(&entry.leaf_input) {
            Ok(v) => v,
            Err(err) => {
                return Err(format!("Invalid leaf_input from '{}': {}", self.log.name, err));
            }
        };
        let extra_bytes = match base64::decode(&entry.extra_data) {
            Ok(v) => v,
            Err(err) => {
                return Err(format!("Invalid extra_data from '{}': {}", self.log.name, err));
            }
        };

        let mut decode_buf = merkle_leaf_bytes.clone();
        let merkle_leaf = MerkleTreeLeaf::from_bytes(&mut decode_buf);

        if decode_buf.len() != 0 {
            return Err(format!("Left over bytes on merkle leaf from '{}'", self.log.name));
        }

        Ok(Entry {
            index,
            tree_leaf: merkle_leaf,
            leaf_bytes: merkle_leaf_bytes,
            extra_data: extra_bytes,
        })
    }
}

impl std::iter::Iterator for GetEntries<'_> {
    type Item = Result<Vec<Entry>, String>;

    fn next(&mut self) -> Option<Self::Item> {

        let offset = std::cmp::max(self.offset + self.start_from, self.size-1);

        if offset == std::cmp::max(offset + 100, self.size-1) {
            return None
        }

        let r = match self.client.get(format!("{}ct/v1/get-entries", self.log.url))
            .query(&[
                ("start", offset.to_string()),
                ("end", std::cmp::max(offset + 100, self.size-1).to_string())
            ])
            .send() {
            Ok(v) => v,
            Err(err) => {
                return Some(Err(format!("error connecting to '{}' to get entries: {}", self.log.name, err)));
            }
        };
        let url = r.url().to_string();
        let status = r.status();
        let entries = match r.json::<EntriesJSON>() {
            Ok(v) => v,
            Err(err) => {
                warn!("Failing on '{:?}': {}", url, status);
                return Some(Err(format!("error decoding entries from '{}': {}", self.log.name, err)));
            }
        };

        let returned_entries = entries.entries.len() as u64;
        if returned_entries == 0 {
            return Some(Err(format!("entries above {} not yet available", offset)));
        }

        self.offset += returned_entries;
        let to_download = self.size - self.start_from;
        let downloaded = self.offset;

        if downloaded % 100 == 0 || downloaded == to_download {
            let now = Utc::now();
            let download_diff = (downloaded - self.last_offset) as f64;
            let time_diff = (now - self.last_offset_time).num_seconds() as f64;
            let download_rate = download_diff / time_diff;
            self.last_offset = downloaded;
            self.last_offset_time = now;
            let download_percent = ((downloaded as f64) / (to_download as f64)) * 100.0;
            info!("Downloaded {} of {} total '{}' entries ({:.2}%, {:.2} entries/sec)", downloaded, to_download, self.log.name, download_percent, download_rate);
        }

        let remaining = self.size - self.offset;
        let out = entries.entries.into_iter().take(remaining as usize)
            .enumerate()
            .map(|(i, e)| self.decode_entry(&e, offset + i as u64)).collect::<Result<Vec<_>, _>>();

        Some(out)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.size as usize, Some(self.size as usize))
    }
}

impl std::iter::ExactSizeIterator for GetEntries<'_> {
    fn len(&self) -> usize {
        self.size as usize
    }
}

pub fn get_sth(client: &reqwest::blocking::Client, log: &CTLog) -> Result<SignedTreeHead, String> {
    let sth = match match client.get(format!("{}ct/v1/get-sth", log.url)).send() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Error connecting to '{}' to get latest STH: {}", log.name, err));
        }
    }.json::<SignedTreeHeadJSON>() {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Error decoding STH from '{}': {}", log.name, err));
        }
    };

    let timestamp = Utc.timestamp_millis(sth.timestamp as i64);
    if timestamp + log.mmd < Utc::now() {
        return Err(format!("STH on '{}' older than MMD", log.name));
    }

    let root_hash = match match base64::decode(sth.sha256_root_hash) {
        Ok(v) => <[u8; 32]>::try_from(v),
        Err(err) => {
            return Err(format!("Invalid root hash received from '{}': {}", log.name, err));
        }
    } {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Invalid root hash received from '{}', unexpected length {}", log.name, err.len()));
        }
    };
    let tree_head_signature_bytes = match base64::decode(sth.tree_head_signature) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Invalid tree head signature received from '{}': {}", log.name, err));
        }
    };
    let tree_head_signature = match DigitallySigned::from_u8(&tree_head_signature_bytes) {
        Some(s) => s,
        None => {
            return Err(format!("Invalid tree head signature received from '{}'", log.name));
        }
    };

    let tree_head_signature_source = TreeHeadSignature {
        version: Version::V1,
        signature_type: SignatureType::TreeHash,
        timestamp: sth.timestamp.into(),
        tree_size: sth.tree_size.into(),
        sha256_root_hash: root_hash,
    };
    let tree_head_signature_source_bytes = any_as_u8_slice(&tree_head_signature_source);

    let mut verifier = match openssl::sign::Verifier::new(
        (&tree_head_signature.algorithm.hash).into(),
        &log.public_key,
    ) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Unable to verify tree head signature received from '{}': {}", log.name, err));
        }
    };
    let verified = match verifier.verify_oneshot(
        &tree_head_signature.signature, &tree_head_signature_source_bytes,
    ) {
        Ok(v) => v,
        Err(err) => {
            return Err(format!("Unable to verify tree head signature received from '{}': {}", log.name, err));
        }
    };

    if !verified {
        return Err(format!("Invalid signature on tree head from '{}'", log.name));
    }

    Ok(SignedTreeHead {
        tree_size: sth.tree_size,
        timestamp,
        sha256_root_hash: root_hash,
    })
}