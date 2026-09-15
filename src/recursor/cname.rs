// src/recursor/cname.rs
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

pub fn extract_cname_target(record: &Record, name: &Name) -> Option<Name> {
    if record.name() == name && record.record_type() == RecordType::CNAME {
        if let RData::CNAME(cname) = record.data() {
            return Some(cname.0.clone());
        }
    }
    None
}

/// Merges an alias redirection hop into the target response.
pub fn merge_redirection_response(
    orig_name: &Name,
    orig_type: RecordType,
    first_hop_msg: &Message,
    final_msg: Message,
) -> Message {
    let mut final_response = Message::new();
    final_response.set_id(final_msg.id());
    final_response.set_message_type(MessageType::Response);
    final_response.set_op_code(final_msg.op_code());
    final_response.set_authoritative(final_msg.authoritative());
    final_response.set_truncated(final_msg.truncated());
    final_response.set_recursion_desired(final_msg.recursion_desired());
    final_response.set_recursion_available(final_msg.recursion_available());
    final_response.set_authentic_data(final_msg.authentic_data());
    final_response.set_checking_disabled(final_msg.checking_disabled());
    final_response.set_response_code(final_msg.response_code());

    let mut q = Query::new();
    q.set_name(orig_name.clone());
    q.set_query_type(orig_type);
    q.set_query_class(DNSClass::IN);
    final_response.add_query(q);

    // 1. Answers: first-hop records followed by final target answers
    for r in first_hop_msg.answers() {
        final_response.add_answer(r.clone());
    }

    for r in final_msg.answers() {
        if !final_response
            .answers()
            .iter()
            .any(|existing| existing == r)
        {
            final_response.add_answer(r.clone());
        }
    }

    // 2. Authority: final target authority records, plus any DNSSEC proofs from first hop
    for r in final_msg.name_servers() {
        final_response.add_name_server(r.clone());
    }

    for r in first_hop_msg.name_servers() {
        let is_dnssec = matches!(
            r.record_type(),
            RecordType::NSEC | RecordType::NSEC3 | RecordType::RRSIG
        );
        if is_dnssec
            && !final_response
                .name_servers()
                .iter()
                .any(|existing| existing == r)
        {
            final_response.add_name_server(r.clone());
        }
    }

    // 3. Additionals
    for r in final_msg.additionals() {
        if r.record_type() != RecordType::OPT {
            final_response.add_additional(r.clone());
        }
    }

    for r in first_hop_msg.additionals() {
        let is_dnssec = matches!(r.record_type(), RecordType::RRSIG | RecordType::DNSKEY);
        if is_dnssec
            && !final_response
                .additionals()
                .iter()
                .any(|existing| existing == r)
        {
            final_response.add_additional(r.clone());
        }
    }

    if let Some(edns) = final_msg.extensions().as_ref() {
        final_response.set_edns(edns.clone());
    }

    final_response
}
