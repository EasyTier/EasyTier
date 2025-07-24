use std::fmt::Display;

include!(concat!(env!("OUT_DIR"), "/acl.rs"));

impl Display for ConnTrackEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let src = self
            .src_addr
            .as_ref()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        let dst = self
            .dst_addr
            .as_ref()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".to_string());
        let last_seen = chrono::DateTime::<chrono::Utc>::from_timestamp(self.last_seen as i64, 0)
            .unwrap()
            .with_timezone(&chrono::Local);
        let created_at = chrono::DateTime::<chrono::Utc>::from_timestamp(self.created_at as i64, 0)
            .unwrap()
            .with_timezone(&chrono::Local);
        write!(
            f,
            "[src: {}, dst: {}, proto: {:?}, state: {:?}, pkts: {}, bytes: {}, created: {}, last_seen: {}]",
            src,
            dst,
            Protocol::try_from(self.protocol).unwrap_or(Protocol::Unspecified),
            ConnState::try_from(self.state).unwrap_or(ConnState::Invalid),
            self.packet_count,
            self.byte_count,
            created_at,
            last_seen
        )
    }
}

impl Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[name: '{}', prio: {}, action: {:?}, enabled: {}, proto: {:?}, ports: {:?}, src_ports: {:?}, src_ips: {:?}, dst_ips: {:?}, stateful: {}, rate: {}, burst: {}]",
            self.name,
            self.priority,
            Action::try_from(self.action).unwrap_or(Action::Noop),
            self.enabled,
            Protocol::try_from(self.protocol).unwrap_or(Protocol::Unspecified),
            self.ports,
            self.source_ports,
            self.source_ips,
            self.destination_ips,
            self.stateful,
            self.rate_limit,
            self.burst_limit
        )
    }
}

impl Display for StatItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[pkts: {}, bytes: {}]",
            self.packet_count, self.byte_count
        )
    }
}

impl Display for AclStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "AclStats:")?;
        writeln!(f, "  Global:")?;
        for (k, v) in &self.global {
            writeln!(f, "    {}: {}", k, v)?;
        }
        writeln!(f, "  ConnTrack:")?;
        for entry in &self.conn_track {
            writeln!(f, "    {}", entry)?;
        }
        writeln!(f, "  Rules:")?;
        for rule_stat in &self.rules {
            if let Some(rule) = &rule_stat.rule {
                write!(f, "    {} ", rule)?;
            } else {
                write!(f, "    <default/none> ")?;
            }
            if let Some(stat) = &rule_stat.stat {
                writeln!(f, "{}", stat)?;
            } else {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
