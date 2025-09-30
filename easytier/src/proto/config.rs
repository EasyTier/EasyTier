include!(concat!(env!("OUT_DIR"), "/config.rs"));

pub struct Patchable<T> {
    pub action: Option<ConfigPatchAction>,
    pub value: Option<T>,
}

impl From<PortForwardPatch> for Patchable<crate::common::config::PortForwardConfig> {
    fn from(patch: PortForwardPatch) -> Self {
        Patchable {
            action: ConfigPatchAction::try_from(patch.action).ok(),
            value: patch.cfg.map(Into::into),
        }
    }
}

impl From<RoutePatch> for Patchable<cidr::Ipv4Cidr> {
    fn from(value: RoutePatch) -> Self {
        Patchable {
            action: ConfigPatchAction::try_from(value.action).ok(),
            value: value.cidr.map(Into::into),
        }
    }
}

impl From<ExitNodePatch> for Patchable<std::net::IpAddr> {
    fn from(value: ExitNodePatch) -> Self {
        Patchable {
            action: ConfigPatchAction::try_from(value.action).ok(),
            value: value.node.map(Into::into),
        }
    }
}

impl From<StringPatch> for Patchable<String> {
    fn from(value: StringPatch) -> Self {
        Patchable {
            action: ConfigPatchAction::try_from(value.action).ok(),
            value: Some(value.value),
        }
    }
}

impl From<UrlPatch> for Patchable<url::Url> {
    fn from(value: UrlPatch) -> Self {
        Patchable {
            action: ConfigPatchAction::try_from(value.action).ok(),
            value: value.url.map(Into::into),
        }
    }
}

pub fn patch_vec<T>(v: &mut Vec<T>, patches: Vec<Patchable<T>>)
where
    T: PartialEq,
{
    for patch in patches {
        match patch.action {
            Some(ConfigPatchAction::Add) => {
                if let Some(value) = patch.value {
                    v.push(value);
                }
            }
            Some(ConfigPatchAction::Remove) => {
                if let Some(value) = patch.value {
                    v.retain(|x| x != &value);
                }
            }
            Some(ConfigPatchAction::Clear) => {
                v.clear();
            }
            None => {}
        }
    }
}
