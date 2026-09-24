//
// Port supporting code from wireguard-windows, as used by 3rd-party/wireguard-go, to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/winipcfg/luid.go
//
// ATTENTION: NOT included are DNS() and SetDNS() - functions to query and set DNS servers for a network interface.
//

use super::types::*;
use cidr::Ipv4Inet;
use cidr::Ipv6Inet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use winapi::shared::{ifdef::NET_LUID, netioapi::*, nldef::*, winerror::*, ws2def::*};

pub struct InterfaceLuid {
    luid: NET_LUID,
}

impl InterfaceLuid {
    /// luid_from_index function converts a local index for a network interface to the locally unique identifier (LUID) for the interface.
    /// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceindextoluid
    pub fn luid_from_index(interface_index: u32) -> Result<Self, NETIO_STATUS> {
        let mut interface_luid = NET_LUID::default();

        let result = unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut interface_luid) };

        if NO_ERROR == result {
            Ok(Self {
                luid: interface_luid,
            })
        } else {
            Err(result)
        }
    }

    /// add_ipv4_address method adds new unicast IP address to the interface. Corresponds to CreateUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
    pub fn add_ipv4_address(&self, address: &Ipv4Inet) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe { *row.Address.Ipv4_mut() = convert_ipv4addr_to_sockaddr(&address.address()) };
        row.OnLinkPrefixLength = address.network_length();

        let result = unsafe { CreateUnicastIpAddressEntry(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// add_ipv6_address method adds new unicast IP address to the interface. Corresponds to CreateUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
    pub fn add_ipv6_address(&self, address: &Ipv6Inet) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe { *row.Address.Ipv6_mut() = convert_ipv6addr_to_sockaddr(&address.address()) };
        row.OnLinkPrefixLength = address.network_length();

        let result = unsafe { CreateUnicastIpAddressEntry(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// delete_ipv4_address method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
    pub fn delete_ipv4_address(&self, address: &Ipv4Inet) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe { *row.Address.Ipv4_mut() = convert_ipv4addr_to_sockaddr(&address.address()) };
        row.OnLinkPrefixLength = address.network_length();

        let result = unsafe { DeleteUnicastIpAddressEntry(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// delete_ipv6_address method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
    pub fn delete_ipv6_address(&self, address: &Ipv6Inet) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe { *row.Address.Ipv6_mut() = convert_ipv6addr_to_sockaddr(&address.address()) };
        row.OnLinkPrefixLength = address.network_length();

        let result = unsafe { DeleteUnicastIpAddressEntry(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// flush_ip_addresses method deletes all interface's unicast IP addresses.
    pub fn flush_ip_addresses(&self, address_family: ADDRESS_FAMILY) -> Result<(), NETIO_STATUS> {
        let mut p_table: PMIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        let result = unsafe { GetUnicastIpAddressTable(address_family, &mut p_table) };
        if NO_ERROR != result {
            return Err(result);
        }

        assert!(!p_table.is_null());
        let num_entries = unsafe { *p_table }.NumEntries;
        let x_table = unsafe { *p_table }.Table.as_ptr();
        for i in 0..num_entries {
            let current_entry = unsafe { x_table.add(i as _) };
            if unsafe { (*current_entry).InterfaceLuid.Value } == self.luid.Value {
                unsafe { DeleteUnicastIpAddressEntry(current_entry) };
            }
        }

        unsafe { FreeMibTable(p_table as _) };

        Ok(())
    }

    /// flush_ipv4_addresses method deletes all interface's unicast IP addresses.
    pub fn flush_ipv4_addresses(&self) -> Result<(), NETIO_STATUS> {
        self.flush_ip_addresses(AF_INET as _)
    }

    /// flush_ipv6_addresses method deletes all interface's unicast IP addresses.
    pub fn flush_ipv6_addresses(&self) -> Result<(), NETIO_STATUS> {
        self.flush_ip_addresses(AF_INET6 as _)
    }

    /// add_route_ipv4 method adds a route to the interface. Corresponds to CreateIpForwardEntry2 function, with added splitDefault feature.
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2)
    pub fn add_route_ipv4(
        &self,
        destination: &Ipv4Inet,
        next_hop: &Ipv4Addr,
        metric: u32,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe {
            *row.DestinationPrefix.Prefix.Ipv4_mut() =
                convert_ipv4addr_to_sockaddr(&destination.address())
        };
        row.DestinationPrefix.PrefixLength = destination.network_length();

        unsafe { *row.NextHop.Ipv4_mut() = convert_ipv4addr_to_sockaddr(next_hop) };

        row.Metric = metric;

        let result = unsafe { CreateIpForwardEntry2(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// add_route_ipv6 method adds a route to the interface. Corresponds to CreateIpForwardEntry2 function, with added splitDefault feature.
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createipforwardentry2)
    pub fn add_route_ipv6(
        &self,
        destination: &Ipv6Inet,
        next_hop: &Ipv6Addr,
        metric: u32,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        unsafe {
            *row.DestinationPrefix.Prefix.Ipv6_mut() =
                convert_ipv6addr_to_sockaddr(&destination.address())
        };
        row.DestinationPrefix.PrefixLength = destination.network_length();

        unsafe { *row.NextHop.Ipv6_mut() = convert_ipv6addr_to_sockaddr(next_hop) };

        row.Metric = metric;

        let result = unsafe { CreateIpForwardEntry2(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// add_routes_ipv4 method adds multiple routes to the interface
    pub fn add_routes_ipv4(
        &self,
        routes_data: impl IntoIterator<Item = RouteDataIpv4>,
    ) -> Result<(), NETIO_STATUS> {
        for rd in routes_data.into_iter().enumerate() {
            self.add_route_ipv4(&rd.1.destination, &rd.1.next_hop, rd.1.metric)?;
        }
        Ok(())
    }

    /// add_routes_ipv6 method adds multiple routes to the interface
    pub fn add_routes_ipv6(
        &self,
        routes_data: impl IntoIterator<Item = RouteDataIpv6>,
    ) -> Result<(), NETIO_STATUS> {
        for rd in routes_data.into_iter().enumerate() {
            self.add_route_ipv6(&rd.1.destination, &rd.1.next_hop, rd.1.metric)?;
        }
        Ok(())
    }

    /// delete_route_ipv4 method deletes a route that matches the criteria. Corresponds to DeleteIpForwardEntry2 function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteipforwardentry2).
    pub fn delete_route_ipv4(
        &self,
        destination: &Ipv4Inet,
        next_hop: &Ipv4Addr,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceLuid = self.luid;

        unsafe {
            *row.DestinationPrefix.Prefix.Ipv4_mut() =
                convert_ipv4addr_to_sockaddr(&destination.address())
        };
        row.DestinationPrefix.PrefixLength = destination.network_length();

        unsafe { *row.NextHop.Ipv4_mut() = convert_ipv4addr_to_sockaddr(next_hop) };

        let result = unsafe { GetIpForwardEntry2(&mut row) };
        if NO_ERROR != result {
            return Err(result);
        }

        let result = unsafe { DeleteIpForwardEntry2(&row) };
        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// delete_route_ipv6 method deletes a route that matches the criteria. Corresponds to DeleteIpForwardEntry2 function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteipforwardentry2).
    pub fn delete_route_ipv6(
        &self,
        destination: &Ipv6Inet,
        next_hop: &Ipv6Addr,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceLuid = self.luid;

        unsafe {
            *row.DestinationPrefix.Prefix.Ipv6_mut() =
                convert_ipv6addr_to_sockaddr(&destination.address())
        };
        row.DestinationPrefix.PrefixLength = destination.network_length();

        unsafe { *row.NextHop.Ipv6_mut() = convert_ipv6addr_to_sockaddr(next_hop) };

        let result = unsafe { GetIpForwardEntry2(&mut row) };
        if NO_ERROR != result {
            return Err(result);
        }

        let result = unsafe { DeleteIpForwardEntry2(&row) };

        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// Sets MTU on the interface
    /// TODO: Set IP and other things in here too, so the code is more organized
    pub fn set_iface_config(&self, mtu: u32) -> Result<(), NETIO_STATUS> {
        // SAFETY: Both NET_LUID_LH unions should be the same. We're just copying out
        // the u64 value and re-wrapping it, since wintun doesn't refer to the windows
        // crate's version of NET_LUID_LH.
        if let Err(e) = self.try_set_mtu(AF_INET as ADDRESS_FAMILY, mtu) {
            tracing::warn!("Failed to set IPv4 MTU: {:?}", e);
        }
        if let Err(e) = self.try_set_mtu(AF_INET6 as ADDRESS_FAMILY, mtu) {
            tracing::warn!("Failed to set IPv6 MTU: {:?}", e);
        }
        Ok(())
    }

    fn try_set_mtu(&self, family: ADDRESS_FAMILY, mut mtu: u32) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceLuid: self.luid,
            ..Default::default()
        };

        // SAFETY: TODO
        let error = unsafe { GetIpInterfaceEntry(&mut row) };
        if error != NO_ERROR {
            if family == (AF_INET6 as ADDRESS_FAMILY) && error == ERROR_NOT_FOUND {
                tracing::debug!(?family, "Couldn't set MTU, maybe IPv6 is disabled.");
            } else {
                tracing::warn!(?family, "Couldn't set MTU: {}", error);
            }
            return Err(error);
        }

        if family == (AF_INET6 as ADDRESS_FAMILY) {
            // ipv6 mtu must be at least 1280
            mtu = 1280.max(mtu);
        }

        // https://stackoverflow.com/questions/54857292/setipinterfaceentry-returns-error-invalid-parameter
        row.SitePrefixLength = 0;

        row.NlMtu = mtu;

        // SAFETY: TODO
        let ret = unsafe { SetIpInterfaceEntry(&mut row) };
        if NO_ERROR == ret { Ok(()) } else { Err(ret) }
    }
}
