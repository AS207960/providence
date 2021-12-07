#[macro_use]
extern crate log;

use prost::Message;
use chrono::prelude::*;
use x509_parser::prelude::*;

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

fn general_name_to_name(name: &GeneralName) -> proto::Name {
    proto::Name {
        value: match name {
            GeneralName::RFC822Name(v) => Some(proto::name::Value::Email(v.to_string())),
            GeneralName::DNSName(v) => Some(proto::name::Value::Dns(v.to_string())),
            GeneralName::URI(v) => Some(proto::name::Value::Uri(v.to_string())),
            GeneralName::DirectoryName(v) => Some(proto::name::Value::Name(v.to_string_with_registry(oid_registry()).unwrap_or_default())),
            GeneralName::RegisteredID(v) => Some(proto::name::Value::Oid(v.to_string())),
            GeneralName::IPAddress(v) => match v.len() {
                4 => Some(proto::name::Value::IpAddress(proto::IpAddr {
                    ip_addr: Some(proto::ip_addr::IpAddr::V4(u32::from_be_bytes(TryInto::<[u8; 4]>::try_into(*v).unwrap()))),
                })),
                16 => Some(proto::name::Value::IpAddress(proto::IpAddr {
                    ip_addr: Some(proto::ip_addr::IpAddr::V6(v.to_vec())),
                })),
                _ => None
            },
            _ => None,
        }
    }
}

fn tbs_to_leaf(tbs: TbsCertificate, raw: &[u8]) -> proto::LeafCertificate {
    proto::LeafCertificate {
        raw: raw.to_vec(),
        serial_number: tbs.serial.to_bytes_be(),
        not_before: chrono_to_proto(Some(Utc.timestamp(tbs.validity.not_before.timestamp(), 0))),
        not_after: chrono_to_proto(Some(Utc.timestamp(tbs.validity.not_after.timestamp(), 0))),
        subject: tbs.subject.to_string_with_registry(oid_registry()).unwrap_or_default(),
        issuer: tbs.issuer.to_string_with_registry(oid_registry()).unwrap_or_default(),
        extensions: Some(proto::CertExtensions {
            basic_constraints: tbs.basic_constraints().map(|(c, bc)| {
                proto::BasicConstraints {
                    critical: c,
                    ca: bc.ca,
                    path_len_constraint: bc.path_len_constraint,
                }
            }),
            key_usage: tbs.key_usage().map(|(c, ku)| {
                proto::KeyUsage {
                    critical: c,
                    digital_signature: ku.digital_signature(),
                    non_repudiation: ku.non_repudiation(),
                    key_encipherment: ku.key_encipherment(),
                    data_encipherment: ku.data_encipherment(),
                    key_agreement: ku.key_agreement(),
                    key_cert_sign: ku.key_cert_sign(),
                    crl_sign: ku.crl_sign(),
                    encipher_only: ku.encipher_only(),
                    decipher_only: ku.decipher_only(),
                }
            }),
            extended_key_usage: tbs.extended_key_usage().map(|(c, eku)| {
                proto::ExtendedKeyUsage {
                    critical: c,
                    any: eku.any,
                    server_auth: eku.server_auth,
                    client_auth: eku.client_auth,
                    email_protection: eku.email_protection,
                    time_stamping: eku.time_stamping,
                    ocsp_stapling: eku.ocsp_signing,
                    code_signing: eku.code_signing,
                    other: eku.other.iter().map(|o| o.to_string()).collect(),
                }
            }),
            subject_alternative_names: tbs.subject_alternative_name().map(|(c, san)| {
                proto::SubjectAlternativeNames {
                    critical: c,
                    names: san.general_names.iter().map(general_name_to_name).collect(),
                }
            }),
            subject_key_identifier: tbs.find_extension(&oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
                .and_then(|e| match e.parsed_extension() {
                    ParsedExtension::SubjectKeyIdentifier(v) => Some(proto::SubjectKeyIdentifier {
                        critical: e.critical,
                        ki: v.0.to_vec(),
                    }),
                    _ => None
                }),
            authority_key_identifier: tbs.find_extension(&oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
                .and_then(|e| match e.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(v) => Some(proto::AuthorityKeyIdentifier {
                        critical: e.critical,
                        ki: v.key_identifier.as_ref().map(|i| i.0.to_vec()),
                        serial: v.authority_cert_serial.map(|s| s.to_vec()),
                    }),
                    _ => None
                }),
            authority_info_access: tbs.find_extension(&oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
                .and_then(|e| match e.parsed_extension() {
                    ParsedExtension::AuthorityInfoAccess(v) => {
                        let map = v.as_hashmap();
                        Some(proto::AuthorityInfoAccess {
                            critical: e.critical,
                            ocsp: map.get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP)
                                .map(|d|
                                    d.into_iter().map(|n| general_name_to_name(*n)).collect()
                                ).unwrap_or_default(),
                            ca_issuers: map.get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS)
                                .map(|d|
                                    d.into_iter().map(|n| general_name_to_name(*n)).collect()
                                ).unwrap_or_default(),
                            ca_repository: map.get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_REPOSITORY)
                                .map(|d|
                                    d.into_iter().map(|n| general_name_to_name(*n)).collect()
                                ).unwrap_or_default(),
                            crls: map.get(&oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_HTTP_CRLS)
                                .map(|d|
                                    d.into_iter().map(|n| general_name_to_name(*n)).collect()
                                ).unwrap_or_default(),
                        })
                    }
                    _ => None
                }),
        }),
    }
}

fn tbs_and_pre_cert_eq(tbs_cert: &TbsCertificate, pre_cert: &X509Certificate) -> bool {
    if tbs_cert.version != pre_cert.tbs_certificate.version {
        return false;
    }

    if tbs_cert.serial != pre_cert.tbs_certificate.serial {
        return false;
    }

    if tbs_cert.signature.algorithm != pre_cert.tbs_certificate.signature.algorithm {
        return false;
    }

    if tbs_cert.signature.parameters != pre_cert.tbs_certificate.signature.parameters {
        return false;
    }

    if tbs_cert.validity != pre_cert.tbs_certificate.validity {
        return false;
    }

    if tbs_cert.subject != pre_cert.tbs_certificate.subject {
        return false;
    }

    if tbs_cert.subject_pki != pre_cert.tbs_certificate.subject_pki {
        return false;
    }

    let tbs_extensions = tbs_cert.iter_extensions()
        .filter(|e| e.oid != oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER);
    let pre_cert_extensions = pre_cert.tbs_certificate.iter_extensions()
        .filter(|e| e.oid != oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .collect::<Vec<_>>();

    for ext in tbs_extensions {
        if !pre_cert_extensions.contains(&ext) {
            return false;
        }
    }

    true
}

fn main() {
    pretty_env_logger::init();

    info!("Starting RabbitMQ client");
    let mut amqp_conn = amiquip::Connection::insecure_open(&std::env::var("RABBITMQ_URL").expect("No RABBITMQ_URL variable"))
        .expect("Unable to connect to RabbitMQ server");
    let amqp_channel1 = amqp_conn.open_channel(None).expect("Unable to open RabbitMQ channel");
    amqp_channel1.qos(0, 100, false).expect("Unable to setup QoS settings");
    let amqp_channel2 = amqp_conn.open_channel(None).expect("Unable to open RabbitMQ channel");

    let listen_queue = amqp_channel1.queue_declare("", amiquip::QueueDeclareOptions {
        exclusive: true,
        ..amiquip::QueueDeclareOptions::default()
    }).expect("Unable to declare RabbitMQ queue");

    amqp_channel1.queue_bind(
        listen_queue.name(), "providence_raw", "",
        amiquip::FieldTable::new(),
    ).expect("Unable to bind RabbitMQ queue to exchange");

    let pub_exchange = amqp_channel2.exchange_declare(
        amiquip::ExchangeType::Fanout,
        "providence_parsed",
        amiquip::ExchangeDeclareOptions {
            durable: true,
            ..amiquip::ExchangeDeclareOptions::default()
        },
    ).expect("Unable to declare RabbitMQ exchange");

    let event_consumer = listen_queue.consume(amiquip::ConsumerOptions {
        no_ack: false,
        ..Default::default()
    })
        .expect("Unable to start consuming on RabbitMQ queue");

    info!("RabbitMQ listener started");
    for message in event_consumer.receiver().iter() {
        match message {
            amiquip::ConsumerMessage::Delivery(delivery) => {
                match proto::RawEvent::decode(delivery.body.as_slice()) {
                    Ok(evt) => {
                        match evt.event {
                            Some(proto::raw_event::Event::LeafEvent(le)) => {
                                let source = if let Some(s) = le.source {
                                    proto::CertificateSource {
                                        id: s.id,
                                        url: s.url,
                                        name: s.name,
                                    }
                                } else {
                                    continue;
                                };

                                let evt = match le.entry {
                                    Some(proto::leaf_event::Entry::TimestampedEntry(te)) => {
                                        match te.entry {
                                            Some(proto::timestamped_entry::Entry::PreCert(pc)) => {
                                                let tbs = match TbsCertificate::from_der(&pc.tbs_certificate) {
                                                    Ok(l) => l,
                                                    Err(err) => {
                                                        error!("Unable to parse PreCert TBS: {}", err);
                                                        continue;
                                                    }
                                                };
                                                let leaf = match X509Certificate::from_der(&pc.leaf_certificate) {
                                                    Ok(l) => l,
                                                    Err(err) => {
                                                        error!("Unable to parse PreCert: {}", err);
                                                        continue;
                                                    }
                                                };

                                                let mut chain = vec![];
                                                for cert in &pc.certificate_chain {
                                                    match X509Certificate::from_der(cert) {
                                                        Ok(l) => chain.push((l, cert)),
                                                        Err(err) => {
                                                            error!("Unable to parse PreCert: {}", err);
                                                            continue;
                                                        }
                                                    };
                                                }

                                                proto::parsed_event::Event::Cert(proto::Certificate {
                                                    cert_index: le.index,
                                                    cert_url: le.url,
                                                    pre_cert: true,
                                                    certs_consistent: tbs_and_pre_cert_eq(&tbs.1, &leaf.1),
                                                    source: Some(source),
                                                    chain: chain.into_iter()
                                                        .map(|(c, r)| tbs_to_leaf(c.1.tbs_certificate, r)).collect(),
                                                    leaf_cert: Some(tbs_to_leaf(tbs.1, &pc.leaf_certificate)),
                                                    seen: evt.timestamp,
                                                    timestamp: te.timestamp,
                                                })
                                            }
                                            Some(proto::timestamped_entry::Entry::Asn1Cert(asn1_cert)) => {
                                                let leaf = match X509Certificate::from_der(&asn1_cert.leaf_certificate) {
                                                    Ok(l) => l,
                                                    Err(err) => {
                                                        error!("Unable to parse ASN1Cert: {}", err);
                                                        continue;
                                                    }
                                                };

                                                let mut chain = vec![];
                                                for cert in &asn1_cert.certificate_chain {
                                                    match X509Certificate::from_der(cert) {
                                                        Ok(l) => chain.push((l, cert)),
                                                        Err(err) => {
                                                            error!("Unable to parse ASN1Cert: {}", err);
                                                            continue;
                                                        }
                                                    };
                                                }

                                                proto::parsed_event::Event::Cert(proto::Certificate {
                                                    cert_index: le.index,
                                                    cert_url: le.url,
                                                    pre_cert: false,
                                                    source: Some(source),
                                                    certs_consistent: true,
                                                    chain: chain.into_iter()
                                                        .map(|(c, r)| tbs_to_leaf(c.1.tbs_certificate, r)).collect(),
                                                    leaf_cert: Some(tbs_to_leaf(leaf.1.tbs_certificate, &asn1_cert.leaf_certificate)),
                                                    seen: evt.timestamp,
                                                    timestamp: te.timestamp,
                                                })
                                            }
                                            _ => continue
                                        }
                                    }
                                    _ => continue
                                };

                                let parsed_evt = proto::ParsedEvent {
                                    event: Some(evt)
                                };
                                let mut buf = Vec::new();
                                buf.reserve(parsed_evt.encoded_len());
                                parsed_evt.encode(&mut buf).unwrap();

                                pub_exchange.publish(amiquip::Publish {
                                    body: &buf,
                                    routing_key: "".to_string(),
                                    immediate: false,
                                    mandatory: false,
                                    properties: amiquip::AmqpProperties::default(),
                                }).expect("Unable to publish message");
                            }
                            _ => {}
                        }
                        delivery.ack(&amqp_channel1).expect("Unable to ack message");
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
}
