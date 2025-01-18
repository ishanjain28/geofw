#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Queue, RingBuf},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
};
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
static REQUEST: RingBuf = RingBuf::with_byte_size(128, 0);

#[map]
static RESPONSE: Queue<bool> = Queue::with_max_entries(128, 0);

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

    if let Some(mut buf) = REQUEST.reserve::<Ipv4Addr>(0) {
        buf.write(source);
        buf.submit(0);
    }

    let mut result = false;
    let mut n = 0;
    while n < 10 {
        if let Some(r) = RESPONSE.pop() {
            result = r;
            break;
        }
        n += 1;
    }

    if result {
        Ok(xdp_action::XDP_PASS)
    } else {
        info!(&ctx, "ipv4 source = {} result = {}", source, result as u8);

        Ok(xdp_action::XDP_DROP)
    }
}

fn filter_ipv6_packet(ctx: XdpContext) -> Result<u32, u32> {
    let ip: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
    let source = unsafe { (*ip).src_addr() };

    // info!(&ctx, "ipv6 source = {}", source);
    if let Some(mut buf) = REQUEST.reserve::<Ipv6Addr>(0) {
        buf.write(source);
        buf.submit(0);
    }

    let mut result = false;
    let mut n = 0;
    while n < 10 {
        if let Some(r) = RESPONSE.pop() {
            result = r;
            break;
        }
        n += 1;
    }

    if result {
        Ok(xdp_action::XDP_PASS)
    } else {
        info!(&ctx, "ipv4 source = {} result = {}", source, result as u8);

        Ok(xdp_action::XDP_DROP)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
