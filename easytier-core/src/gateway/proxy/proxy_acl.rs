use std::sync::Arc;

use easytier_proto::acl::{Action, ChainType};
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio_util::io::InspectReader;

use crate::peers::acl::{filter::AclFilter, processor::PacketInfo};

#[derive(Clone)]
pub struct ProxyAclHandler {
    pub acl_filter: Arc<AclFilter>,
    pub packet_info: PacketInfo,
    pub chain_type: ChainType,
}

impl ProxyAclHandler {
    pub fn handle_packet(&self, buf: &[u8]) -> anyhow::Result<()> {
        self.handle_packet_size(buf.len())
    }

    pub fn handle_packet_size(&self, packet_size: usize) -> anyhow::Result<()> {
        let mut packet_info = self.packet_info.clone();
        packet_info.packet_size = packet_size;
        let processor = self.acl_filter.get_processor();
        let ret = processor.process_packet(&packet_info, self.chain_type);
        self.acl_filter
            .handle_acl_result(&ret, &packet_info, self.chain_type, &processor);
        if !matches!(ret.action, Action::Allow) {
            anyhow::bail!("acl denied");
        }

        Ok(())
    }

    pub async fn copy_bidirection_with_acl(
        &self,
        src: impl AsyncRead + AsyncWrite + Unpin,
        mut dst: impl AsyncRead + AsyncWrite + Unpin,
    ) -> anyhow::Result<()> {
        let (src_reader, src_writer) = tokio::io::split(src);
        let src_reader = InspectReader::new(src_reader, |buf| {
            let _ = self.handle_packet(buf);
        });
        let mut src = tokio::io::join(src_reader, src_writer);

        copy_bidirectional(&mut src, &mut dst).await?;
        Ok(())
    }
}
