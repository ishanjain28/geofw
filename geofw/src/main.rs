mod maxmind;

use anyhow::Context as _;
use aya::{
    maps::{Queue, RingBuf},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use log::{debug, warn};
use maxminddb::geoip2;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "enp6s18")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let maxmind_db = maxmind::MaxmindDB::new("./geofw/GeoLite2-City.mmdb");
    println!("{:?}", maxmind_db);
    maxmind_db.read_binary_search_tree();
    return Ok(());

    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/geofw"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("geofw").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // TODO(ishan)
    // Download geolite2 db
    // Keep it updated, once every 24h
    // Read from request ring buffer in a loop
    // do lookup and write responses to the response buffer

    std::thread::spawn(move || {
        let mut request = RingBuf::try_from(ebpf.take_map("REQUEST").unwrap()).unwrap();
        let mut response = Queue::try_from(ebpf.take_map("RESPONSE").unwrap()).unwrap();

        let db_reader = maxminddb::Reader::open_readfile("./geofw/GeoLite2-City.mmdb")
            .expect("error in opening geolite2 db");

        loop {
            while let Some(msg) = request.next() {
                let msg = &*msg;
                let addr = match msg.len() {
                    4 => IpAddr::V4(Ipv4Addr::from([msg[0], msg[1], msg[2], msg[3]])),
                    16 => IpAddr::V6(Ipv6Addr::from([
                        msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
                        msg[9], msg[10], msg[11], msg[12], msg[13], msg[14], msg[15],
                    ])),

                    _ => unreachable!(),
                };

                let result = db_reader
                    .lookup(addr)
                    .map(|x: geoip2::City| {
                        x.country
                            .map(|country| country.iso_code.map(|x| x != "IN").unwrap_or(true))
                            .unwrap_or(true)
                    })
                    .unwrap_or(true);

                response
                    .push(result as u8, 0)
                    .expect("error in writing result to queue");
                // println!("wrote {} for {:?}", result, addr);
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
