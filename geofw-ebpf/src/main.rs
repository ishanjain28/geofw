#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, warn};
use core::{mem, net::IpAddr};
use geofw_common::{MaxmindDb, ProgramParameters, BLOCK_MARKER};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[xdp]
pub fn geofw(ctx: XdpContext) -> u32 {
    match try_geofw(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[map]
static BLOCKED_ASN: Array<u8> = Array::with_max_entries(1024 * 1024 * 20, 0); // 10MiB

#[map]
static BLOCKED_COUNTRY: Array<u8> = Array::with_max_entries(1024 * 1024 * 50, 0);

#[map]
static PARAMETERS: HashMap<u8, u32> = HashMap::with_max_entries(1024, 0);

fn try_geofw(ctx: XdpContext) -> Result<u32, u32> {
    let eth: *const EthHdr = ptr_at(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    match unsafe { (*eth).ether_type } {
        EtherType::Ipv4 => filter_ip_packet(ctx),
        EtherType::Ipv6 => filter_ipv6_packet(ctx),

        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn filter_ip_packet(ctx: XdpContext) -> Result<u32, u32> {
    let ip: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let source = unsafe { (*ip).src_addr() };

    let result = should_block(&ctx, MaxmindDb::Asn, &BLOCKED_ASN, IpAddr::V4(source))
        || should_block(
            &ctx,
            MaxmindDb::Country,
            &BLOCKED_COUNTRY,
            IpAddr::V4(source),
        );

    if result {
        debug!(&ctx, "ipv4 source = {} blocked = {}", source, result as u8);

        Ok(xdp_action::XDP_DROP)
    } else {
        //  info!(&ctx, "ipv6 source = {} result = {}", source, result as u8);
        Ok(xdp_action::XDP_PASS)
    }
}

fn filter_ipv6_packet(ctx: XdpContext) -> Result<u32, u32> {
    let ip: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let source = unsafe { (*ip).src_addr() };

    let result = should_block(&ctx, MaxmindDb::Asn, &BLOCKED_ASN, IpAddr::V6(source))
        || should_block(
            &ctx,
            MaxmindDb::Country,
            &BLOCKED_COUNTRY,
            IpAddr::V6(source),
        );

    if result {
        debug!(&ctx, "ipv6 source = {} blocked = {}", source, result as u8);

        Ok(xdp_action::XDP_DROP)
    } else {
        //   info!(&ctx, "ipv6 source = {} result = {}", source, result as u8);

        Ok(xdp_action::XDP_PASS)
    }
}

pub fn should_block(ctx: &XdpContext, db_name: MaxmindDb, map: &Array<u8>, addr: IpAddr) -> bool {
    let record_size = match db_name {
        MaxmindDb::Country => unsafe {
            PARAMETERS.get(&(ProgramParameters::CountryRecordSize as u8))
        },
        MaxmindDb::Asn => unsafe { PARAMETERS.get(&(ProgramParameters::AsnRecordSize as u8)) },
    };
    let Some(&record_size) = record_size else {
        return false;
    };

    let node_count = match db_name {
        MaxmindDb::Country => unsafe {
            PARAMETERS.get(&(ProgramParameters::CountryNodeCount as u8))
        },
        MaxmindDb::Asn => unsafe { PARAMETERS.get(&(ProgramParameters::AsnNodeCount as u8)) },
    };
    let Some(&node_count) = node_count else {
        return false;
    };

    let node_size = record_size as usize * 2 / 8;
    let mut node = 0;
    let mut ip = match addr {
        IpAddr::V4(a) => a.to_bits() as u128,
        IpAddr::V6(a) => a.to_bits(),
    };

    let mut i = 0;
    while i < 128 && node < node_count {
        let bit = ip & (1 << 127);
        ip <<= 1;

        let mut slice = [0; 8];
        for (i, v) in slice.iter_mut().enumerate().take(node_size) {
            *v = match map.get(node * node_size as u32 + i as u32) {
                Some(&v) => v,
                None => {
                    warn!(
                        ctx,
                        "error in reading position = {}",
                        node * node_size as u32 + i as u32,
                    );
                    return false;
                }
            }
        }
        node = node_from_bytes(slice, if bit > 0 { 1 } else { 0 }, record_size as u16);
        i += 1;
    }

    node == BLOCK_MARKER
}

fn node_from_bytes(n: [u8; 8], bit: u8, record_size: u16) -> u32 {
    match record_size {
        28 => {
            if bit == 0 {
                u32::from_be_bytes([(n[3] & 0b1111_0000) >> 4, n[0], n[1], n[2]])
            } else {
                u32::from_be_bytes([n[3] & 0b0000_1111, n[4], n[5], n[6]])
            }
        }
        24 => {
            if bit == 0 {
                u32::from_be_bytes([0, n[0], n[1], n[2]])
            } else {
                u32::from_be_bytes([0, n[3], n[4], n[5]])
            }
        }

        // this should never reach
        _ => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
