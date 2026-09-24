//! Minimal protobuf wire editing used by OSPF route reflection.
//!
//! Route calculation uses generated prost types. This module only keeps the
//! original `RoutePeerInfo` bytes and replaces the two fields that credential
//! filtering is allowed to change, leaving every other field byte-for-byte
//! intact.

use bytes::Bytes;
use prost::{
    Message,
    encoding::{
        DecodeContext, WireType, decode_key, decode_varint, encode_key, encode_varint, skip_field,
    },
};
use thiserror::Error;

use crate::proto::peer_rpc::{RoutePeerInfo, SyncRouteInfoRequest};

const SYNC_ROUTE_PEER_INFOS_TAG: u32 = 4;
const ROUTE_PEER_INFOS_ITEM_TAG: u32 = 1;
const ROUTE_PEER_INFO_PROXY_CIDRS_TAG: u32 = 5;
const ROUTE_PEER_INFO_FEATURE_FLAG_TAG: u32 = 11;
const ROUTE_PEER_INFO_CREDENTIAL_PROOF_TAG: u32 = 19;
const FEATURE_FLAG_IS_CREDENTIAL_PEER_TAG: u32 = 8;
const CREDENTIAL_PROOF_CREDENTIAL_TAG: u32 = 1;

pub(crate) type RawRoutePeerInfo = Bytes;

#[derive(Debug, Error)]
pub(crate) enum WireError {
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    #[error("protobuf field {tag} has wire type {actual:?}, expected {expected:?}")]
    WrongWireType {
        tag: u32,
        actual: WireType,
        expected: WireType,
    },
    #[error("protobuf length-delimited field is larger than the remaining input")]
    TruncatedLengthDelimited,
    #[error("raw RoutePeerInfo count does not match the decoded request")]
    PeerInfoCountMismatch,
}

type Result<T> = std::result::Result<T, WireError>;

#[derive(Clone, Copy)]
struct WireField<'a> {
    tag: u32,
    wire_type: WireType,
    encoded: &'a [u8],
    length_delimited: Option<&'a [u8]>,
}

fn parse_fields(message: &[u8]) -> Result<Vec<WireField<'_>>> {
    let mut input = message;
    let mut fields = Vec::new();

    while !input.is_empty() {
        let start = message.len() - input.len();
        let (tag, wire_type) = decode_key(&mut input)?;
        let length_delimited = if wire_type == WireType::LengthDelimited {
            let len = usize::try_from(decode_varint(&mut input)?)
                .map_err(|_| WireError::TruncatedLengthDelimited)?;
            if len > input.len() {
                return Err(WireError::TruncatedLengthDelimited);
            }
            let (payload, remaining) = input.split_at(len);
            input = remaining;
            Some(payload)
        } else {
            skip_field(wire_type, tag, &mut input, DecodeContext::default())?;
            None
        };
        let end = message.len() - input.len();
        fields.push(WireField {
            tag,
            wire_type,
            encoded: &message[start..end],
            length_delimited,
        });
    }

    Ok(fields)
}

fn length_delimited_fields(message: &[u8], tag: u32) -> Result<Vec<&[u8]>> {
    parse_fields(message)?
        .into_iter()
        .filter(|field| field.tag == tag)
        .map(|field| {
            field.length_delimited.ok_or(WireError::WrongWireType {
                tag,
                actual: field.wire_type,
                expected: WireType::LengthDelimited,
            })
        })
        .collect()
}

fn replace_fields(
    message: &[u8],
    tag: u32,
    expected_wire_type: WireType,
    replacement: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(message.len() + replacement.len());
    for field in parse_fields(message)? {
        if field.tag != tag {
            output.extend_from_slice(field.encoded);
            continue;
        }
        if field.wire_type != expected_wire_type {
            return Err(WireError::WrongWireType {
                tag,
                actual: field.wire_type,
                expected: expected_wire_type,
            });
        }
    }
    output.extend_from_slice(replacement);
    Ok(output)
}

fn append_length_delimited_field(output: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    encode_key(tag, WireType::LengthDelimited, output);
    encode_varint(payload.len() as u64, output);
    output.extend_from_slice(payload);
}

fn append_varint_field(output: &mut Vec<u8>, tag: u32, value: u64) {
    encode_key(tag, WireType::Varint, output);
    encode_varint(value, output);
}

fn merged_length_delimited_field(message: &[u8], tag: u32) -> Result<Vec<u8>> {
    let values = length_delimited_fields(message, tag)?;
    let total_len = values.iter().map(|value| value.len()).sum();
    let mut merged = Vec::with_capacity(total_len);
    for value in values {
        merged.extend_from_slice(value);
    }
    Ok(merged)
}

pub(crate) fn raw_route_peer_info(info: &RoutePeerInfo) -> RawRoutePeerInfo {
    Bytes::from(info.encode_to_vec())
}

pub(crate) fn extract_route_peer_infos(request: &[u8]) -> Result<Vec<RawRoutePeerInfo>> {
    let mut result = Vec::new();
    for peer_infos in length_delimited_fields(request, SYNC_ROUTE_PEER_INFOS_TAG)? {
        result.extend(
            length_delimited_fields(peer_infos, ROUTE_PEER_INFOS_ITEM_TAG)?
                .into_iter()
                .map(Bytes::copy_from_slice),
        );
    }
    Ok(result)
}

pub(crate) fn encode_sync_route_request(
    request: &SyncRouteInfoRequest,
    raw_peer_infos: &[RawRoutePeerInfo],
) -> Result<Vec<u8>> {
    let decoded_count = request
        .peer_infos
        .as_ref()
        .map(|peer_infos| peer_infos.items.len())
        .unwrap_or_default();
    if decoded_count != raw_peer_infos.len() {
        return Err(WireError::PeerInfoCountMismatch);
    }

    let mut request_without_peer_infos = request.clone();
    request_without_peer_infos.peer_infos = None;
    let mut output = request_without_peer_infos.encode_to_vec();
    if request.peer_infos.is_some() {
        let mut peer_infos = Vec::new();
        for info in raw_peer_infos {
            append_length_delimited_field(&mut peer_infos, ROUTE_PEER_INFOS_ITEM_TAG, info);
        }
        append_length_delimited_field(&mut output, SYNC_ROUTE_PEER_INFOS_TAG, &peer_infos);
    }
    Ok(output)
}

pub(crate) fn patch_credential_route_peer_info(
    raw: &RawRoutePeerInfo,
    proxy_cidrs: &[String],
) -> Result<RawRoutePeerInfo> {
    let mut proxy_cidr_fields = Vec::new();
    for cidr in proxy_cidrs {
        append_length_delimited_field(
            &mut proxy_cidr_fields,
            ROUTE_PEER_INFO_PROXY_CIDRS_TAG,
            cidr.as_bytes(),
        );
    }
    let route_info = replace_fields(
        raw,
        ROUTE_PEER_INFO_PROXY_CIDRS_TAG,
        WireType::LengthDelimited,
        &proxy_cidr_fields,
    )?;

    // Singular message fields merge when they occur more than once. Concatenating
    // their payloads preserves that protobuf behavior before changing tag 8.
    let feature_flag =
        merged_length_delimited_field(&route_info, ROUTE_PEER_INFO_FEATURE_FLAG_TAG)?;
    let mut credential_flag = Vec::new();
    append_varint_field(&mut credential_flag, FEATURE_FLAG_IS_CREDENTIAL_PEER_TAG, 1);
    let feature_flag = replace_fields(
        &feature_flag,
        FEATURE_FLAG_IS_CREDENTIAL_PEER_TAG,
        WireType::Varint,
        &credential_flag,
    )?;
    let mut feature_flag_field = Vec::new();
    append_length_delimited_field(
        &mut feature_flag_field,
        ROUTE_PEER_INFO_FEATURE_FLAG_TAG,
        &feature_flag,
    );

    Ok(Bytes::from(replace_fields(
        &route_info,
        ROUTE_PEER_INFO_FEATURE_FLAG_TAG,
        WireType::LengthDelimited,
        &feature_flag_field,
    )?))
}

pub(crate) fn raw_credential_bytes(
    raw_route_info: &RawRoutePeerInfo,
    proof_idx: usize,
) -> Result<Option<Bytes>> {
    let proofs = length_delimited_fields(raw_route_info, ROUTE_PEER_INFO_CREDENTIAL_PROOF_TAG)?;
    let Some(proof) = proofs.get(proof_idx) else {
        return Ok(None);
    };
    let credentials = length_delimited_fields(proof, CREDENTIAL_PROOF_CREDENTIAL_TAG)?;
    if credentials.is_empty() {
        return Ok(None);
    }

    // Multiple occurrences of a singular message field merge. Concatenation is
    // the wire-equivalent merged message and keeps nested unknown fields intact.
    let total_len = credentials.iter().map(|value| value.len()).sum();
    let mut merged = Vec::with_capacity(total_len);
    for credential in credentials {
        merged.extend_from_slice(credential);
    }
    Ok(Some(Bytes::from(merged)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        common::PeerFeatureFlag,
        peer_rpc::{RoutePeerInfos, TrustedCredentialPubkey, TrustedCredentialPubkeyProof},
    };

    fn encoded_varint_field(tag: u32, value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        append_varint_field(&mut output, tag, value);
        output
    }

    fn encoded_length_delimited_field(tag: u32, payload: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        append_length_delimited_field(&mut output, tag, payload);
        output
    }

    fn encoded_fields(message: &[u8], tag: u32) -> Vec<Vec<u8>> {
        parse_fields(message)
            .unwrap()
            .into_iter()
            .filter(|field| field.tag == tag)
            .map(|field| field.encoded.to_vec())
            .collect()
    }

    #[test]
    fn patch_preserves_top_level_and_nested_unknown_fields() {
        const TOP_LEVEL_UNKNOWN_TAG: u32 = 100;
        const FEATURE_UNKNOWN_TAG: u32 = 101;

        let mut feature_flag = PeerFeatureFlag {
            avoid_relay_data: true,
            ..Default::default()
        }
        .encode_to_vec();
        feature_flag.extend(encoded_varint_field(FEATURE_UNKNOWN_TAG, 42));

        let info = RoutePeerInfo {
            peer_id: 7,
            proxy_cidrs: vec!["10.0.0.0/8".to_owned()],
            ..Default::default()
        };
        let mut raw = info.encode_to_vec();
        raw.extend(encoded_length_delimited_field(
            ROUTE_PEER_INFO_FEATURE_FLAG_TAG,
            &feature_flag,
        ));
        raw.extend(encoded_varint_field(TOP_LEVEL_UNKNOWN_TAG, 99));

        let top_level_unknown = encoded_fields(&raw, TOP_LEVEL_UNKNOWN_TAG);
        let nested_unknown = encoded_fields(&feature_flag, FEATURE_UNKNOWN_TAG);
        let patched =
            patch_credential_route_peer_info(&Bytes::from(raw), &["10.1.0.0/16".to_owned()])
                .unwrap();

        assert_eq!(
            encoded_fields(&patched, TOP_LEVEL_UNKNOWN_TAG),
            top_level_unknown
        );
        let patched_feature =
            merged_length_delimited_field(&patched, ROUTE_PEER_INFO_FEATURE_FLAG_TAG).unwrap();
        assert_eq!(
            encoded_fields(&patched_feature, FEATURE_UNKNOWN_TAG),
            nested_unknown
        );

        let decoded = RoutePeerInfo::decode(patched).unwrap();
        assert_eq!(decoded.proxy_cidrs, ["10.1.0.0/16"]);
        assert!(decoded.feature_flag.unwrap().is_credential_peer);
    }

    #[test]
    fn multi_hop_sync_keeps_raw_peer_info_exactly() {
        let info = RoutePeerInfo {
            peer_id: 9,
            ..Default::default()
        };
        let mut raw = info.encode_to_vec();
        raw.extend(encoded_length_delimited_field(120, b"future"));
        let raw = Bytes::from(raw);
        let request = SyncRouteInfoRequest {
            my_peer_id: 1,
            peer_infos: Some(RoutePeerInfos { items: vec![info] }),
            ..Default::default()
        };

        let first_hop = encode_sync_route_request(&request, std::slice::from_ref(&raw)).unwrap();
        let first_hop_raw = extract_route_peer_infos(&first_hop).unwrap();
        assert_eq!(first_hop_raw.as_slice(), std::slice::from_ref(&raw));
        assert_eq!(
            SyncRouteInfoRequest::decode(first_hop.as_slice())
                .unwrap()
                .peer_infos,
            request.peer_infos
        );

        let second_hop = encode_sync_route_request(&request, &first_hop_raw).unwrap();
        assert_eq!(extract_route_peer_infos(&second_hop).unwrap(), [raw]);
    }

    #[test]
    fn credential_hmac_uses_exact_nested_message_bytes() {
        let secret = "wire-test-secret";
        let credential = TrustedCredentialPubkey {
            pubkey: vec![3; 32],
            ..Default::default()
        };
        let mut raw_credential = credential.encode_to_vec();
        raw_credential.extend(encoded_varint_field(100, 1234));
        let hmac = TrustedCredentialPubkeyProof::generate_credential_hmac_from_bytes(
            &raw_credential,
            secret,
        );

        let mut raw_proof =
            encoded_length_delimited_field(CREDENTIAL_PROOF_CREDENTIAL_TAG, &raw_credential);
        raw_proof.extend(encoded_length_delimited_field(2, &hmac));
        let mut raw_route_info = RoutePeerInfo {
            peer_id: 11,
            ..Default::default()
        }
        .encode_to_vec();
        raw_route_info.extend(encoded_length_delimited_field(
            ROUTE_PEER_INFO_CREDENTIAL_PROOF_TAG,
            &raw_proof,
        ));

        let extracted = raw_credential_bytes(&Bytes::from(raw_route_info), 0)
            .unwrap()
            .unwrap();
        assert_eq!(extracted, raw_credential);

        let proof = TrustedCredentialPubkeyProof {
            credential: Some(credential),
            credential_hmac: hmac,
        };
        assert!(proof.verify_credential_hmac_with_bytes(&extracted, secret));
    }
}
