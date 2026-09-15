// src/recursor/dname.rs
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use std::str::FromStr;

pub const DNAME_RECORD_TYPE: RecordType = RecordType::Unknown(39);

/// RFC 6672 DNAME suffix substitution with strict length validation.
pub fn dname_substitute(
    name: &Name,
    dname_owner: &Name,
    target: &Name,
) -> Result<Name, ResponseCode> {
    if !dname_owner.zone_of(name) || dname_owner == name {
        return Err(ResponseCode::FormErr);
    }
    let name_str = name.to_string().to_lowercase();
    let owner_str = dname_owner.to_string().to_lowercase();
    if !name_str.ends_with(&owner_str) {
        return Err(ResponseCode::FormErr);
    }
    let prefix = &name_str[..name_str.len() - owner_str.len()];
    let target_str = target.to_string();
    let new_name_str = format!("{}{}", prefix, target_str);

    // RFC 6672 §2.2: Name length limit (255) and label length limit (63)
    if new_name_str.len() > 255 {
        return Err(ResponseCode::YXDomain);
    }
    for label in new_name_str.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(ResponseCode::YXDomain);
        }
    }

    Name::from_str(&new_name_str).map_err(|_| ResponseCode::YXDomain)
}

pub fn extract_dname_target(record: &Record) -> Option<Name> {
    if record.record_type() == DNAME_RECORD_TYPE {
        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        record.data().emit(&mut encoder).ok()?;
        let mut decoder = BinDecoder::new(&buf);
        return Name::read(&mut decoder).ok();
    }
    None
}
