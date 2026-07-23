#[cfg(feature = "management")]
#[path = "management_state_enabled.rs"]
mod selected;

#[cfg(not(feature = "management"))]
#[path = "management_state_disabled.rs"]
mod selected;

pub(super) use selected::ManagementState;
