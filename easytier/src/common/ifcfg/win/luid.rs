//
// Port supporting code from wireguard-windows, as used by 3rd-party/wireguard-go, to Rust
// This file implements functionality similar to: wireguard-windows/tunnel/winipcfg/luid.go
//
// ATTENTION: NOT included are DNS() and SetDNS() - functions to query and set DNS servers for a network interface.
//

use super::netsh;
use super::types::*;
use cidr::Ipv4Inet;
use cidr::Ipv6Inet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use winapi::shared::{
    guiddef::GUID, ifdef::NET_LUID, netioapi::*, nldef::*, winerror::*, ws2def::*, ws2ipdef::*,
};

pub struct InterfaceLuid {
    luid: NET_LUID,
}

impl InterfaceLuid {
    pub fn new(luid_value: u64) -> Self {
        InterfaceLuid {
            luid: winapi::shared::ifdef::NET_LUID_LH { Value: luid_value },
        }
    }

    pub fn luid(&self) -> NET_LUID {
        self.luid
    }

    /// get_ip_interface method retrieves IP information for the specified interface on the local computer.
    pub fn get_ip_interface(
        &self,
        family: ADDRESS_FAMILY,
    ) -> Result<MIB_IPINTERFACE_ROW, NETIO_STATUS> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.Family = family;

        let result = unsafe { GetIpInterfaceEntry(&mut row) };
        if NO_ERROR == result {
            Ok(row)
        } else {
            Err(result)
        }
    }

    /// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
    /// If only InterfaceIndex was specified, SetIpInterfaceEntry() will modify ipif with a correct InterfaceLuid
    pub fn set_ip_interface(&self, ipif: *mut MIB_IPINTERFACE_ROW) -> Result<(), NETIO_STATUS> {
        let result = unsafe { SetIpInterfaceEntry(ipif) };
        if NO_ERROR == result {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// get_interface method retrieves information for the specified adapter on the local computer.
    /// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getifentry2
    pub fn get_interface(&self) -> Result<MIB_IF_ROW2, NETIO_STATUS> {
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: self.luid,
            ..MIB_IF_ROW2::default()
        };

        let result = unsafe { GetIfEntry2(&mut row) };
        if NO_ERROR == result {
            Ok(row)
        } else {
            Err(result)
        }
    }

    /// GUID method converts a locally unique identifier (LUID) for a network interface to a globally unique identifier (GUID) for the interface.
    /// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceluidtoguid
    pub fn get_guid(&self) -> Result<GUID, NETIO_STATUS> {
        let mut interface_guid = GUID::default();

        let result = unsafe { ConvertInterfaceLuidToGuid(&self.luid, &mut interface_guid) };

        if NO_ERROR == result {
            Ok(interface_guid)
        } else {
            Err(result)
        }
    }

    /// luid_from_guid function converts a globally unique identifier (GUID) for a network interface to the locally unique identifier (LUID) for the interface.
    /// https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-convertinterfaceguidtoluid
    pub fn luid_from_guid(interface_guid: &GUID) -> Result<Self, NETIO_STATUS> {
        let mut interface_luid = NET_LUID::default();

        let result = unsafe { ConvertInterfaceGuidToLuid(interface_guid, &mut interface_luid) };

        if NO_ERROR == result {
            Ok(Self {
                luid: interface_luid,
            })
        } else {
            Err(result)
        }
    }

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

    /// get_from_ipv4_address method returns MibUnicastIPAddressRow struct that matches to provided 'ip' argument. Corresponds to GetUnicastIpAddressEntry
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddressentry)
    pub fn get_from_ipv4_address(
        &self,
        ip: &Ipv4Addr,
    ) -> Result<MIB_UNICASTIPADDRESS_ROW, NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        unsafe { *row.Address.Ipv4_mut() = convert_ipv4addr_to_sockaddr(ip) };

        let result = unsafe { GetUnicastIpAddressEntry(&mut row) };

        if NO_ERROR == result {
            Ok(row)
        } else {
            Err(result)
        }
    }

    /// get_from_ipv6_address method returns MibUnicastIPAddressRow struct that matches to provided 'ip' argument. Corresponds to GetUnicastIpAddressEntry
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getunicastipaddressentry)
    pub fn get_from_ipv6_address(
        &self,
        ip: &Ipv6Addr,
    ) -> Result<MIB_UNICASTIPADDRESS_ROW, NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        unsafe { *row.Address.Ipv6_mut() = convert_ipv6addr_to_sockaddr(ip) };

        let result = unsafe { GetUnicastIpAddressEntry(&mut row) };

        if NO_ERROR == result {
            Ok(row)
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

    /// add_ipv4_addresses method adds multiple new unicast IP addresses to the interface. Corresponds to CreateUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
    pub fn add_ipv4_addresses(
        &self,
        addresses: impl IntoIterator<Item = Ipv4Inet>,
    ) -> Result<(), NETIO_STATUS> {
        for ip in addresses.into_iter().enumerate() {
            self.add_ipv4_address(&ip.1)?;
        }
        Ok(())
    }

    /// add_ipv6_addresses method adds multiple new unicast IP addresses to the interface. Corresponds to CreateUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-createunicastipaddressentry).
    pub fn add_ipv6_addresses(
        &self,
        addresses: impl IntoIterator<Item = Ipv6Inet>,
    ) -> Result<(), NETIO_STATUS> {
        for ip in addresses.into_iter().enumerate() {
            self.add_ipv6_address(&ip.1)?;
        }
        Ok(())
    }

    /// set_ipv4_addresses method sets new unicast IP addresses to the interface.
    pub fn set_ipv4_addresses(
        &self,
        addresses: impl IntoIterator<Item = Ipv4Inet>,
    ) -> Result<(), NETIO_STATUS> {
        self.flush_ipv4_addresses()?;
        self.add_ipv4_addresses(addresses)?;
        Ok(())
    }

    /// set_ipv6_addresses method sets new unicast IP addresses to the interface.
    pub fn set_ipv6_addresses(
        &self,
        addresses: impl IntoIterator<Item = Ipv6Inet>,
    ) -> Result<(), NETIO_STATUS> {
        self.flush_ipv6_addresses()?;
        self.add_ipv6_addresses(addresses)?;
        Ok(())
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

    /// delete_ipv4_address method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
    pub fn delete_ipv4_address2(
        &self,
        address: *const SOCKADDR_IN,
        prefix_len: u8,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        assert!(!address.is_null());
        unsafe { *row.Address.Ipv4_mut() = *address };
        row.OnLinkPrefixLength = prefix_len;

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

    /// delete_ipv6_address method deletes interface's unicast IP address. Corresponds to DeleteUnicastIpAddressEntry function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-deleteunicastipaddressentry).
    pub fn delete_ipv6_address2(
        &self,
        address: *const SOCKADDR_IN6,
        prefix_len: u8,
    ) -> Result<(), NETIO_STATUS> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };

        row.InterfaceLuid = self.luid;
        row.DadState = IpDadStatePreferred;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;

        assert!(!address.is_null());
        unsafe { *row.Address.Ipv6_mut() = *address };
        row.OnLinkPrefixLength = prefix_len;

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

    /// route_ipv4 method returns route determined with the input arguments. Corresponds to GetIpForwardEntry2 function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardentry2).
    /// NOTE: If the corresponding route isn't found, the method will return error.
    pub fn route_ipv4(
        &self,
        destination: &Ipv4Inet,
        next_hop: &Ipv4Addr,
    ) -> Result<MIB_IPFORWARD_ROW2, NETIO_STATUS> {
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

        let result = unsafe { GetIpForwardEntry2(&mut row) };

        if NO_ERROR == result {
            Ok(row)
        } else {
            Err(result)
        }
    }

    /// route_ipv6 method returns route determined with the input arguments. Corresponds to GetIpForwardEntry2 function
    /// (https://docs.microsoft.com/en-us/windows/desktop/api/netioapi/nf-netioapi-getipforwardentry2).
    /// NOTE: If the corresponding route isn't found, the method will return error.
    pub fn route_ipv6(
        &self,
        destination: &Ipv6Inet,
        next_hop: &Ipv6Addr,
    ) -> Result<MIB_IPFORWARD_ROW2, NETIO_STATUS> {
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

        let result = unsafe { GetIpForwardEntry2(&mut row) };

        if NO_ERROR == result {
            Ok(row)
        } else {
            Err(result)
        }
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

    /// set_routes_ipv4 method sets (flush than add) multiple routes to the interface.
    pub fn set_routes_ipv4(
        &self,
        routes_data: impl IntoIterator<Item = RouteDataIpv4>,
    ) -> Result<(), NETIO_STATUS> {
        self.flush_routes_ipv4()?;
        self.add_routes_ipv4(routes_data)?;
        Ok(())
    }

    /// set_routes_ipv6 method sets (flush than add) multiple routes to the interface.
    pub fn set_routes_ipv6(
        &self,
        routes_data: impl IntoIterator<Item = RouteDataIpv6>,
    ) -> Result<(), NETIO_STATUS> {
        self.flush_routes_ipv6()?;
        self.add_routes_ipv6(routes_data)?;
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

    /// flush_routes method deletes all interface's routes.
    /// It continues on failures, and returns the last error afterwards.
    pub fn flush_routes(&self, address_family: ADDRESS_FAMILY) -> Result<(), NETIO_STATUS> {
        let mut last_error: NETIO_STATUS = NO_ERROR;

        let mut p_table: PMIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let result = unsafe { GetIpForwardTable2(address_family, &mut p_table) };
        if NO_ERROR != result {
            return Err(result);
        }

        assert!(!p_table.is_null());
        let num_entries = unsafe { *p_table }.NumEntries;
        let x_table = unsafe { *p_table }.Table.as_ptr();
        for i in 0..num_entries {
            let current_entry = unsafe { x_table.add(i as _) };
            if unsafe { (*current_entry).InterfaceLuid.Value } == self.luid.Value {
                let result = unsafe { DeleteIpForwardEntry2(current_entry) };
                if NO_ERROR != result {
                    last_error = result;
                }
            }
        }

        unsafe { FreeMibTable(p_table as _) };

        if NO_ERROR == last_error {
            Ok(())
        } else {
            Err(result)
        }
    }

    /// flush_routes_ipv4 method deletes all interface's routes.
    /// It continues on failures, and returns the last error afterwards.
    pub fn flush_routes_ipv4(&self) -> Result<(), NETIO_STATUS> {
        self.flush_routes(AF_INET as _)
    }

    /// flush_routes_ipv6 method deletes all interface's routes.
    /// It continues on failures, and returns the last error afterwards.
    pub fn flush_routes_ipv6(&self) -> Result<(), NETIO_STATUS> {
        self.flush_routes(AF_INET6 as _)
    }

    /// flush_dns method clears all DNS servers associated with the adapter.
    fn flush_dns(&self, family: ADDRESS_FAMILY) -> Result<(), String> {
        let ip_itf = match self.get_ip_interface(family) {
            Ok(ip_itf) => ip_itf,
            Err(_) => {
                return Err(String::from("Failed to obtain interface"));
            }
        };

        netsh::flush_dns(family, ip_itf.InterfaceIndex)
    }

    /// flush_dns_ipv4 method clears all DNS servers associated with the adapter.
    pub fn flush_dns_ipv4(&self) -> Result<(), String> {
        self.flush_dns(AF_INET as _)
    }

    /// flush_dns_ipv6 method clears all DNS servers associated with the adapter.
    pub fn flush_dns_ipv6(&self) -> Result<(), String> {
        self.flush_dns(AF_INET6 as _)
    }

    /// Sets MTU on the interface
    /// TODO: Set IP and other things in here too, so the code is more organized
    pub fn set_iface_config(&self, mtu: u32) -> Result<(), NETIO_STATUS> {
        // SAFETY: Both NET_LUID_LH unions should be the same. We're just copying out
        // the u64 value and re-wrapping it, since wintun doesn't refer to the windows
        // crate's version of NET_LUID_LH.
        self.try_set_mtu(AF_INET as ADDRESS_FAMILY, mtu)?;
        self.try_set_mtu(AF_INET6 as ADDRESS_FAMILY, mtu)?;
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
        if NO_ERROR == ret {
            Ok(())
        } else {
            Err(ret)
        }
    }
}
