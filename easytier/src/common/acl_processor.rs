use easytier_core::peers::acl_config::AclRuleConfig;

use crate::common::{config::ConfigLoader as _, global_ctx::ArcGlobalCtx};

pub(crate) fn runtime_acl_config(global_ctx: &ArcGlobalCtx) -> AclRuleConfig {
    AclRuleConfig {
        acl: global_ctx.config.get_acl(),
        tcp_whitelist: global_ctx.config.get_tcp_whitelist(),
        udp_whitelist: global_ctx.config.get_udp_whitelist(),
        whitelist_priority: None,
    }
}
