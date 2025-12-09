#![allow(clippy::module_inception)]

use prost::DecodeError;

use super::rpc_types;

include!(concat!(env!("OUT_DIR"), "/error.rs"));

impl From<&rpc_types::error::Error> for Error {
    fn from(e: &rpc_types::error::Error) -> Self {
        use super::error::error::ErrorKind as ProtoError;
        match e {
            rpc_types::error::Error::ExecutionError(e) => Self {
                error_kind: Some(ProtoError::ExecuteError(ExecuteError {
                    error_message: format!("{:?}", e),
                })),
            },
            rpc_types::error::Error::DecodeError(_) => Self {
                error_kind: Some(ProtoError::ProstDecodeError(ProstDecodeError {})),
            },
            rpc_types::error::Error::EncodeError(_) => Self {
                error_kind: Some(ProtoError::ProstEncodeError(ProstEncodeError {})),
            },
            rpc_types::error::Error::InvalidMethodIndex(m, s) => Self {
                error_kind: Some(ProtoError::InvalidMethodIndex(InvalidMethodIndex {
                    method_index: *m as u32,
                    service_name: format!("{:?}", s),
                })),
            },
            rpc_types::error::Error::InvalidServiceKey(s, _) => Self {
                error_kind: Some(ProtoError::InvalidService(InvalidService {
                    service_name: format!("{:?}", s),
                })),
            },
            rpc_types::error::Error::MalformatRpcPacket(e) => Self {
                error_kind: Some(ProtoError::MalformatRpcPacket(MalformatRpcPacket {
                    error_message: format!("{:?}", e),
                })),
            },
            rpc_types::error::Error::Timeout(e) => Self {
                error_kind: Some(ProtoError::Timeout(Timeout {
                    error_message: format!("{:?}", e),
                })),
            },
            #[allow(unreachable_patterns)]
            e => Self {
                error_kind: Some(ProtoError::OtherError(OtherError {
                    error_message: format!("{:?}", e),
                })),
            },
        }
    }
}

impl From<&Error> for rpc_types::error::Error {
    fn from(e: &Error) -> Self {
        use super::error::error::ErrorKind as ProtoError;
        match &e.error_kind {
            Some(ProtoError::ExecuteError(e)) => {
                Self::ExecutionError(anyhow::anyhow!(e.error_message.clone()))
            }
            Some(ProtoError::ProstDecodeError(_)) => {
                Self::DecodeError(DecodeError::new("decode error"))
            }
            Some(ProtoError::ProstEncodeError(_)) => {
                Self::DecodeError(DecodeError::new("encode error"))
            }
            Some(ProtoError::InvalidMethodIndex(e)) => {
                Self::InvalidMethodIndex(e.method_index as u8, e.service_name.clone())
            }
            Some(ProtoError::InvalidService(e)) => {
                Self::InvalidServiceKey(e.service_name.clone(), "".to_string())
            }
            Some(ProtoError::MalformatRpcPacket(e)) => {
                Self::MalformatRpcPacket(e.error_message.clone())
            }
            Some(ProtoError::Timeout(e)) => {
                Self::ExecutionError(anyhow::anyhow!(e.error_message.clone()))
            }
            Some(ProtoError::OtherError(e)) => {
                Self::ExecutionError(anyhow::anyhow!(e.error_message.clone()))
            }
            None => Self::ExecutionError(anyhow::anyhow!("unknown error {:?}", e)),
        }
    }
}
