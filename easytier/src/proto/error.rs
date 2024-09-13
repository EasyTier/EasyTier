use prost::DecodeError;

use super::rpc_types;

include!(concat!(env!("OUT_DIR"), "/error.rs"));

impl From<&rpc_types::error::Error> for Error {
    fn from(e: &rpc_types::error::Error) -> Self {
        use super::error::error::Error as ProtoError;
        match e {
            rpc_types::error::Error::ExecutionError(e) => Self {
                error: Some(ProtoError::ExecuteError(ExecuteError {
                    error_message: e.to_string(),
                })),
            },
            rpc_types::error::Error::DecodeError(_) => Self {
                error: Some(ProtoError::ProstDecodeError(ProstDecodeError {})),
            },
            rpc_types::error::Error::EncodeError(_) => Self {
                error: Some(ProtoError::ProstEncodeError(ProstEncodeError {})),
            },
            rpc_types::error::Error::InvalidMethodIndex(m, s) => Self {
                error: Some(ProtoError::InvalidMethodIndex(InvalidMethodIndex {
                    method_index: *m as u32,
                    service_name: s.to_string(),
                })),
            },
            rpc_types::error::Error::InvalidServiceKey(s, _) => Self {
                error: Some(ProtoError::InvalidService(InvalidService {
                    service_name: s.to_string(),
                })),
            },
            rpc_types::error::Error::MalformatRpcPacket(e) => Self {
                error: Some(ProtoError::MalformatRpcPacket(MalformatRpcPacket {
                    error_message: e.to_string(),
                })),
            },
            rpc_types::error::Error::Timeout(e) => Self {
                error: Some(ProtoError::Timeout(Timeout {
                    error_message: e.to_string(),
                })),
            },
            #[allow(unreachable_patterns)]
            e => Self {
                error: Some(ProtoError::OtherError(OtherError {
                    error_message: e.to_string(),
                })),
            },
        }
    }
}

impl From<&Error> for rpc_types::error::Error {
    fn from(e: &Error) -> Self {
        use super::error::error::Error as ProtoError;
        match &e.error {
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
