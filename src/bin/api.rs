#[macro_use]
extern crate rocket;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use chrono::prelude::*;
use rocket::futures::Stream;
use rocket::response::stream::{Event, EventStream};
use prost::Message;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/providence.rs"));
}

#[get("/pingu")]
fn pingu() -> &'static str {
    "NOOT NOOT"
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum FirehoseEvent {
    #[serde(rename = "certificate")]
    Certificate(CertificateEvent)
}

#[derive(Serialize)]
struct CertificateEvent {
    index: u64,
    url: String,
    seen: DateTime<Utc>,
    timestamp: DateTime<Utc>,
    source: CertificateSource,
    pre_cert: bool,
    certs_consistent: bool,
    leaf_certificate: LeafCertificate,
    certificate_chain: Vec<LeafCertificate>,
}

#[derive(Serialize)]
struct CertificateSource {
    name: String,
    url: String,
    id: String,
}

#[derive(Serialize)]
struct LeafCertificate {
    serial_number: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    subject: String,
    issuer: String,
    extensions: CertExtensions,
    raw: String,
}

#[derive(Serialize)]
struct CertExtensions {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<ExtendedKeyUsage>,
    subject_key_identifier: Option<SubjectKeyIdentifier>,
    subject_alternative_names: Option<SubjectAlternativeNames>,
    authority_key_identifier: Option<AuthorityKeyIdentifier>,
    authority_info_access: Option<AuthorityInfoAccess>,
}

#[derive(Serialize)]
struct BasicConstraints {
    critical: bool,
    ca: bool,
    path_len_constraint: Option<u32>,
}

#[derive(Serialize)]
struct KeyUsage {
    critical: bool,
    digital_signature: bool,
    non_repudiation: bool,
    key_encipherment: bool,
    data_encipherment: bool,
    key_agreement: bool,
    key_cert_sign: bool,
    crl_sign: bool,
    encipher_only: bool,
    decipher_only: bool,
}

#[derive(Serialize)]
struct ExtendedKeyUsage {
    critical: bool,
    any: bool,
    server_auth: bool,
    client_auth: bool,
    code_signing: bool,
    email_protection: bool,
    time_stamping: bool,
    ocsp_stapling: bool,
    other: Vec<String>,
}

#[derive(Serialize)]
struct AuthorityKeyIdentifier {
    critical: bool,
    key_identifier: Option<String>,
    serial: Option<String>,
}

#[derive(Serialize)]
struct SubjectKeyIdentifier {
    critical: bool,
    key_identifier: String,
}

#[derive(Serialize)]
struct AuthorityInfoAccess {
    critical: bool,
    ocsp: Vec<Name>,
    ca_repository: Vec<Name>,
    ca_issuers: Vec<Name>,
    crls: Vec<Name>,
}

#[derive(Serialize)]
struct SubjectAlternativeNames {
    critical: bool,
    names: Vec<Name>,
}

#[derive(Serialize)]
#[serde(tag = "type", content = "value")]
enum Name {
    #[serde(rename = "email")]
    Email(String),
    #[serde(rename = "dns")]
    DNS(String),
    #[serde(rename = "uri")]
    URI(String),
    #[serde(rename = "name")]
    Name(String),
    #[serde(rename = "oid")]
    OID(String),
    #[serde(rename = "ipaddr")]
    IPAddress(std::net::IpAddr),
    #[serde(rename = "unknown")]
    Unknown,
}

fn proto_to_chrono(
    time: Option<prost_types::Timestamp>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    match time {
        Some(t) => chrono::Utc
            .timestamp_opt(t.seconds, t.nanos as u32)
            .single(),
        None => None,
    }
}

fn map_name(name: proto::Name) -> Name {
    match name.value {
        Some(proto::name::Value::Email(v)) => Name::Email(v),
        Some(proto::name::Value::Dns(v)) => Name::DNS(v),
        Some(proto::name::Value::Uri(v)) => Name::URI(v),
        Some(proto::name::Value::Name(v)) => Name::Name(v),
        Some(proto::name::Value::Oid(v)) => Name::OID(v),
        Some(proto::name::Value::IpAddress(v)) => match v.ip_addr {
            Some(proto::ip_addr::IpAddr::V4(v4)) => Name::IPAddress(std::net::Ipv4Addr::from(v4).into()),
            Some(proto::ip_addr::IpAddr::V6(v6)) => match TryInto::<[u8; 16]>::try_into(v6) {
                Ok(v6) => Name::IPAddress(std::net::Ipv6Addr::from(v6).into()),
                Err(_) => Name::Unknown,
            },
            None => Name::Unknown,
        },
        None => Name::Unknown,
    }
}

fn map_leaf_cert(cert: proto::LeafCertificate) -> Option<LeafCertificate> {
    let mut s = cert.serial_number.iter()
        .fold(String::with_capacity(3 * cert.serial_number.len()), |a, b| {
            a + &format!("{:02x}:", b)
        });
    s.pop();

    Some(LeafCertificate {
        serial_number: s,
        not_before: proto_to_chrono(cert.not_before)?,
        not_after: proto_to_chrono(cert.not_after)?,
        issuer: cert.issuer,
        subject: cert.subject,
        extensions: cert.extensions.map(|e| CertExtensions {
            basic_constraints: e.basic_constraints.map(|bc| BasicConstraints {
                critical: bc.critical,
                ca: bc.ca,
                path_len_constraint: bc.path_len_constraint,
            }),
            key_usage: e.key_usage.map(|ku| KeyUsage {
                critical: ku.critical,
                digital_signature: ku.digital_signature,
                non_repudiation: ku.non_repudiation,
                key_encipherment: ku.key_encipherment,
                data_encipherment: ku.data_encipherment,
                key_agreement: ku.key_agreement,
                key_cert_sign: ku.key_cert_sign,
                crl_sign: ku.crl_sign,
                encipher_only: ku.encipher_only,
                decipher_only: ku.decipher_only,
            }),
            extended_key_usage: e.extended_key_usage.map(|ku| ExtendedKeyUsage {
                critical: ku.critical,
                any: ku.any,
                server_auth: ku.server_auth,
                client_auth: ku.client_auth,
                code_signing: ku.code_signing,
                email_protection: ku.email_protection,
                time_stamping: ku.time_stamping,
                ocsp_stapling: ku.ocsp_stapling,
                other: ku.other,
            }),
            subject_key_identifier: e.subject_key_identifier.map(|ski| {
                let mut s = ski.ki.iter()
                    .fold(String::with_capacity(3 * ski.ki.len()), |a, b| {
                        a + &format!("{:02x}:", b)
                    });
                s.pop();

                SubjectKeyIdentifier {
                    critical: ski.critical,
                    key_identifier: s,
                }
            }),
            authority_key_identifier: e.authority_key_identifier.map(|aki| {
                let ki = match aki.ki {
                    Some(ki) => {
                        let mut s = ki.iter()
                            .fold(String::with_capacity(3 * ki.len()), |a, b| {
                                a + &format!("{:02x}:", b)
                            });
                        s.pop();
                        Some(s)
                    },
                    None => None
                };
                let s = match aki.serial {
                    Some(s) => {
                        let mut s = s.iter()
                            .fold(String::with_capacity(3 * s.len()), |a, b| {
                                a + &format!("{:02x}:", b)
                            });
                        s.pop();
                        Some(s)
                    },
                    None => None,
                };

                AuthorityKeyIdentifier {
                    critical: aki.critical,
                    key_identifier: ki,
                    serial: s,
                }
            }),
            authority_info_access: e.authority_info_access.map(|a| AuthorityInfoAccess {
                critical: a.critical,
                ocsp: a.ocsp.into_iter().map(map_name).collect(),
                ca_repository: a.ca_repository.into_iter().map(map_name).collect(),
                ca_issuers: a.ca_issuers.into_iter().map(map_name).collect(),
                crls: a.crls.into_iter().map(map_name).collect(),
            }),
            subject_alternative_names: e.subject_alternative_names.map(|a| SubjectAlternativeNames {
                critical: a.critical,
                names: a.names.into_iter().map(map_name).collect(),
            }),
        })?,
        raw: base64::encode(cert.raw),
    })
}

fn map_cert_event(cert: proto::Certificate) -> Option<CertificateEvent> {
    Some(CertificateEvent {
        index: cert.cert_index,
        url: cert.cert_url,
        seen: proto_to_chrono(cert.seen)?,
        timestamp: proto_to_chrono(cert.timestamp)?,
        source: cert.source.map(|s| CertificateSource {
            name: s.name,
            id: s.id,
            url: s.url,
        })?,
        pre_cert: cert.pre_cert,
        certs_consistent: cert.certs_consistent,
        leaf_certificate: map_leaf_cert(cert.leaf_cert?)?,
        certificate_chain: cert.chain.into_iter().map(map_leaf_cert).collect::<Option<Vec<LeafCertificate>>>()?,
    })
}

#[get("/firehose")]
async fn firehose(
    amqp_conn: &rocket::State<tokio::sync::Mutex<amiquip::Connection>>
) -> Result<EventStream<impl Stream<Item=Event>>, rocket::http::Status> {
    let amqp_channel = match amqp_conn.lock().await.open_channel(None) {
        Ok(c) => c,
        Err(err) => {
            error!("Unable to open RabbitMQ channel: {}", err);
            std::process::exit(-1);
            // return Err(rocket::http::Status::InternalServerError);
        }
    };

    let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel(10);

    tokio::task::spawn_blocking(move || {
        let listen_queue = amqp_channel.queue_declare("", amiquip::QueueDeclareOptions {
            exclusive: true,
            auto_delete: true,
            ..amiquip::QueueDeclareOptions::default()
        }).expect("Unable to declare RabbitMQ queue");

        amqp_channel.queue_bind(
            listen_queue.name(), "providence_parsed", "",
            amiquip::FieldTable::new(),
        ).expect("Unable to bind RabbitMQ queue to exchange");

        let event_consumer = listen_queue.consume(amiquip::ConsumerOptions {
            no_ack: false,
            ..Default::default()
        })
            .expect("Unable to start consuming on RabbitMQ queue");

        'outer: for message in event_consumer.receiver().iter() {
            match message {
                amiquip::ConsumerMessage::Delivery(delivery) => {
                    match proto::ParsedEvent::decode(delivery.body.as_slice()) {
                        Ok(evt) => {
                            if let Err(err) = evt_tx.try_send(evt) {
                                match err {
                                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                        event_consumer.cancel().expect("Unable to cancel listener");
                                        break 'outer;
                                    }
                                    tokio::sync::mpsc::error::TrySendError::Full(_) => {}
                                }
                            }
                            delivery.ack(&amqp_channel).expect("Unable to ack message");
                        }
                        Err(err) => {
                            error!("Error decoding message: {}", err);
                        }
                    }
                }
                amiquip::ConsumerMessage::ServerClosedChannel(err)
                | amiquip::ConsumerMessage::ServerClosedConnection(err) => {
                    error!("Error on RabbitMQ: {}", err);
                }
                amiquip::ConsumerMessage::ClientCancelled
                | amiquip::ConsumerMessage::ServerCancelled
                | amiquip::ConsumerMessage::ClientClosedChannel
                | amiquip::ConsumerMessage::ClientClosedConnection => {
                    break;
                }
            }
        }
    });

    let stream = EventStream! {
        while let Some(evt) = evt_rx.recv().await {
            match evt.event {
                Some(proto::parsed_event::Event::Cert(cert)) => {
                    if let Some(cert) = map_cert_event(cert) {
                        yield Event::json(&FirehoseEvent::Certificate(cert));
                    }
                },
                _ => {}
            }
        }
    };

    Ok(stream.heartbeat(tokio::time::Duration::from_secs(15)))
}

#[launch]
fn rocket() -> _ {
    pretty_env_logger::init();

    info!("Starting RabbitMQ client");
    let amqp_conn = amiquip::Connection::insecure_open(&std::env::var("RABBITMQ_URL").expect("No RABBITMQ_URL variable"))
        .expect("Unable to connect to RabbitMQ server");

    rocket::build()
        .manage(tokio::sync::Mutex::new(amqp_conn))
        .mount("/", routes![pingu, firehose])
}