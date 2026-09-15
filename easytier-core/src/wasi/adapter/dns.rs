use std::{io, net::IpAddr, task::Poll};

use crate::{
    host::{
        dns::{DnsQuery, DnsSrvRecord, HostDnsIo},
        socket::HostOperationId,
    },
    wasi::{
        imports::{
            HOST_PENDING, cancel_operation, start_dns_resolve, start_dns_srv, start_dns_txt,
            take_dns_resolve, take_dns_srv, take_dns_txt,
        },
        wire::{
            common::host_error,
            dns::{decode_addresses, decode_srv, decode_txt, encode_query},
        },
    },
};

const MAX_DNS_RESULT_LEN: usize = 1024 * 1024;

#[derive(Default)]
pub struct WasiHostDnsIo;

impl HostDnsIo for WasiHostDnsIo {
    fn submit_resolve(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
        submit_query("start_dns_resolve", operation, query, start_dns_resolve)
    }

    fn take_resolve(&self, operation: HostOperationId) -> Poll<io::Result<Vec<IpAddr>>> {
        take_result(
            "take_dns_resolve",
            operation,
            take_dns_resolve,
            decode_addresses,
        )
    }

    fn submit_txt(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
        submit_query("start_dns_txt", operation, query, start_dns_txt)
    }

    fn take_txt(&self, operation: HostOperationId) -> Poll<io::Result<String>> {
        take_result("take_dns_txt", operation, take_dns_txt, decode_txt)
    }

    fn submit_srv(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
        submit_query("start_dns_srv", operation, query, start_dns_srv)
    }

    fn take_srv(&self, operation: HostOperationId) -> Poll<io::Result<Vec<DnsSrvRecord>>> {
        take_result("take_dns_srv", operation, take_dns_srv, decode_srv)
    }

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        host_status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }
}

fn submit_query(
    name: &'static str,
    operation: HostOperationId,
    query: &DnsQuery,
    submit: unsafe extern "C" fn(u64, u32, u32) -> i32,
) -> io::Result<()> {
    let encoded = encode_query(query)?;
    let length = u32::try_from(encoded.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query is too long"))?;
    host_status(name, unsafe {
        submit(operation.0, encoded.as_ptr() as u32, length)
    })
}

fn take_result<T>(
    name: &'static str,
    operation: HostOperationId,
    take: unsafe extern "C" fn(u64, u32, u32) -> i32,
    decode: fn(&[u8]) -> io::Result<T>,
) -> Poll<io::Result<T>> {
    let required = unsafe { take(operation.0, 0, 0) };
    if required == HOST_PENDING {
        return Poll::Pending;
    }
    if required <= 0 {
        return Poll::Ready(Err(host_error(name, required)));
    }
    let required = usize::try_from(required).expect("positive i32 fits usize");
    if required > MAX_DNS_RESULT_LEN {
        cancel_probed_result(operation);
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host {name} result exceeds {MAX_DNS_RESULT_LEN} bytes"),
        )));
    }
    let mut encoded = vec![0_u8; required];
    let capacity = u32::try_from(required).expect("DNS result limit fits u32");
    let copied = unsafe { take(operation.0, encoded.as_mut_ptr() as u32, capacity) };
    if copied != i32::try_from(required).expect("positive DNS result length fits i32") {
        cancel_probed_result(operation);
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host {name} changed result length from {required} to {copied}"),
        )));
    }
    Poll::Ready(decode(&encoded))
}

fn cancel_probed_result(operation: HostOperationId) {
    // The size probe does not consume host state. A second take may have
    // consumed it before returning a malformed status, so this best-effort
    // ownership cleanup must not hide the original protocol error.
    let _ = unsafe { cancel_operation(operation.0) };
}

fn host_status(name: &'static str, result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(host_error(name, result))
    }
}
