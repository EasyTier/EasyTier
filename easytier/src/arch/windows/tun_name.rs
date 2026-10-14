use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::{
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_NO_SUCH_DEVNODE, CR_SUCCESS,
        },
        Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HLOCAL, LocalFree},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
        System::Threading::{CreateMutexExW, SYNCHRONIZATION_SYNCHRONIZE},
    },
    core::{HSTRING, w},
};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

fn reserve_name(name: &str) -> anyhow::Result<Option<OwnedHandle>> {
    let identity = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, name.to_lowercase().as_bytes());
    let object_name = HSTRING::from(format!("Global\\EasyTier.TunName.{identity}"));
    // Reserve the name by the object's lifetime, without thread ownership or
    // waiting. Windows also closes the handle if the process is terminated.
    let (handle, existed) = unsafe {
        // Service and desktop processes must be able to detect each other's
        // reservations. Grant SYNCHRONIZE only, without modification rights.
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:(A;;0x00100000;;;WD)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            ..Default::default()
        };
        let result = CreateMutexExW(
            Some(&attributes),
            &object_name,
            0,
            SYNCHRONIZATION_SYNCHRONIZE.0,
        );
        let existed = GetLastError() == ERROR_ALREADY_EXISTS;
        LocalFree(Some(HLOCAL(descriptor.0)));
        let handle = result?;
        (OwnedHandle::from_raw_handle(handle.0), existed)
    };
    Ok((!existed).then_some(handle))
}

fn interface_exists(name: &str) -> anyhow::Result<bool> {
    // IP interface tables can retain removed adapters after process exit.
    // Check the device tree: disabled devices still occupy their names, but
    // nonpresent devices left by a terminated process do not.
    let network = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(
        r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}",
    )?;
    for guid in network.enum_keys() {
        let connection = match network.open_subkey(format!(r"{}\Connection", guid?)) {
            Ok(key) => key,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let existing_name: String = connection.get_value("Name")?;
        if !existing_name.eq_ignore_ascii_case(name) {
            continue;
        }
        let instance_id: String = connection.get_value("PnpInstanceID")?;
        let mut dev_inst = 0;
        let result = unsafe {
            CM_Locate_DevNodeW(
                &mut dev_inst,
                &HSTRING::from(instance_id),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };
        match result {
            CR_SUCCESS => return Ok(true),
            CR_NO_SUCH_DEVNODE => continue,
            _ => anyhow::bail!("failed to locate network device {name}: {result:?}"),
        }
    }
    Ok(false)
}

pub(crate) fn reserve_tun_name(requested: &str) -> anyhow::Result<(String, OwnedHandle)> {
    if !requested.is_empty() {
        let handle = reserve_name(requested)?
            .ok_or_else(|| anyhow::anyhow!("TUN name {requested} is already in use"))?;
        return Ok((requested.to_owned(), handle));
    }

    for index in 1..=u32::MAX {
        let name = format!("et_{index}");
        let Some(handle) = reserve_name(&name)? else {
            continue;
        };
        if !interface_exists(&name)? {
            return Ok((name, handle));
        }
    }
    anyhow::bail!("no unused TUN name available")
}

#[cfg(test)]
mod tests {
    use super::reserve_tun_name;
    use std::sync::{Arc, Barrier};

    #[test]
    fn explicit_name_reservation_is_case_insensitive_and_released() {
        let name = format!("et_test_reserve_{}", uuid::Uuid::new_v4().simple());
        let reservation = reserve_tun_name(&name).unwrap();
        let error = reserve_tun_name(&name.to_uppercase()).unwrap_err();
        assert!(error.to_string().contains("is already in use"));
        drop(reservation);
        assert!(reserve_tun_name(&name).is_ok());
    }

    #[test]
    fn concurrent_default_names_are_unique_and_reuse_vacant_slots() {
        let barrier = Arc::new(Barrier::new(8));
        let mut reservations = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        reserve_tun_name("").unwrap()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        reservations.sort_by_key(|(name, _)| name[3..].parse::<u32>().unwrap());
        assert!(
            reservations
                .windows(2)
                .all(|names| names[0].0 != names[1].0)
        );

        let (name, handle) = reservations.remove(0);
        drop(handle);
        let reused = reserve_tun_name("").unwrap();
        assert_eq!(reused.0, name);
    }
}
