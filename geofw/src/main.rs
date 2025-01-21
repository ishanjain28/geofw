mod maxmind;

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, MapData},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use flate2::bufread::GzDecoder;
use fxhash::FxHashSet;
use geofw_common::ProgramParameters;
use log::{debug, info, warn};
use maxmind::ProcessedDb;
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};
use tar::Archive;
use tokio::{signal, time};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub db: Db,
    pub interface: String,
    pub source_countries: FxHashSet<String>,
    pub source_asn: FxHashSet<u32>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Db {
    pub maxmind_key: String,
    pub refresh_interval: i64,
    pub path: String,
}

const COUNTRY_DB: &str = "GeoLite2-Country";
const ASN_DB: &str = "GeoLite2-ASN";

fn read_config(path: &str) -> Result<Config, String> {
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut contents = vec![];
    f.read_to_end(&mut contents).map_err(|e| e.to_string())?;

    serde_json::from_slice(&contents).map_err(|e| e.to_string())
}

fn fetch_geoip_db(config: &Config, db_name: &str) -> Result<ProcessedDb, String> {
    let mut unpack_path = PathBuf::new();
    unpack_path.push(&config.db.path);
    unpack_path.push(format!("{}.mmdb", db_name));

    info!("unpack path = {:?}", unpack_path);

    let url = format!("https://download.maxmind.com/app/geoip_download?edition_id={}&license_key={}&suffix=tar.gz", db_name, config.db.maxmind_key);

    info!("fetching db from = {}", url);

    let response = ureq::get(&url).call();

    let db = match response {
        Ok(v) if v.status() != 200 => {
            warn!("response from maxmind is not 200 = {}", v.status());

            maxmind::MaxmindDB::from_file(&unpack_path.to_string_lossy())?
        }
        Ok(resp) => {
            let reader = resp.into_reader();
            let reader = BufReader::new(reader);
            let tar = GzDecoder::new(reader);
            let mut archive = Archive::new(tar);
            let entries = archive
                .entries()
                .map_err(|e| format!("error in listing files in the archive: {}", e))?;

            let mut db_entry = entries
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|entry| {
                    let path = match entry.path() {
                        Ok(v) => v,
                        Err(_) => return None,
                    };

                    if path.extension().is_none_or(|x| x != "mmdb") {
                        return None;
                    }
                    Some(entry)
                })
                .next()
                .unwrap();

            db_entry.unpack(&unpack_path).map_err(|e| e.to_string())?;

            maxmind::MaxmindDB::from_file(&unpack_path.to_string_lossy())?
        }

        Err(e) => {
            warn!("error in fetching db from maxmind: {}", e);

            maxmind::MaxmindDB::from_file(&unpack_path.to_string_lossy())?
        }
    };

    info!("downloaded {}", db_name);

    match db_name {
        COUNTRY_DB => Ok(db.consume_country_database(&config.source_countries)),
        ASN_DB => Ok(db.consume_asn_database(&config.source_asn)),

        _ => Err("unknown db".to_string()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = read_config("./config.json").expect("error in reading config");

    setup();

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

    let program: &mut Xdp = ebpf.program_mut("geofw").unwrap().try_into()?;
    let mut interval = time::interval(
        chrono::Duration::seconds(config.db.refresh_interval)
            .to_std()
            .unwrap(),
    );

    program.load()?;
    program.attach(&config.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = interval.tick() => {
                info!("updating DB");

                match update_geoip_map(&config, &mut ebpf, COUNTRY_DB, "BLOCKED_COUNTRY") {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("error in updating map {} = {}", COUNTRY_DB, e);
                    }
                }

                match update_geoip_map(&config, &mut ebpf, ASN_DB, "BLOCKED_ASN") {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("error in updating map {} = {}", ASN_DB, e);
                    }
                }
            }
        }
    }

    Ok(())
}

fn update_geoip_map(
    config: &Config,
    ebpf: &mut Ebpf,
    db_name: &str,
    map_name: &str,
) -> Result<(), String> {
    info!("updating maps db_name = {db_name} map_name = {map_name}");

    let mut map = Array::try_from(ebpf.map_mut(map_name).expect("error in getting map"))
        .expect("error in processing map");

    let result = fetch_geoip_db(config, db_name)?;

    info!(
        "set map = {map_name} up to the location = {} record_size = {} node_count = {}",
        result.db.len(),
        result.record_size,
        result.node_count
    );

    for (i, v) in result.db.into_iter().enumerate() {
        map.set(i as u32, v, 0).map_err(|e| e.to_string())?;
    }

    let mut map: HashMap<&mut MapData, u8, u32> = HashMap::try_from(
        ebpf.map_mut("PARAMETERS")
            .expect("error in getting parameter map"),
    )
    .expect("error in processing parameter map");

    match db_name {
        COUNTRY_DB => {
            map.insert(
                ProgramParameters::CountryNodeCount as u8,
                result.node_count,
                0,
            )
            .expect("error in writing country node count to map");
            map.insert(
                ProgramParameters::CountryRecordSize as u8,
                result.record_size as u32,
                0,
            )
            .expect("error in writing country record size to map");
        }
        ASN_DB => {
            map.insert(ProgramParameters::AsnNodeCount as u8, result.node_count, 0)
                .expect("error in writing country node count to map");
            map.insert(
                ProgramParameters::AsnRecordSize as u8,
                result.record_size as u32,
                0,
            )
            .expect("error in writing country record size to map");
        }

        _ => unreachable!(),
    }

    Ok(())
}

fn setup() {
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
}
