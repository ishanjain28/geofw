mod maxmind;

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap, MapData},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use flate2::bufread::GzDecoder;
use fxhash::FxHashSet;
use geofw_common::{MaxmindDbType, ProgramParameters};
use log::{debug, info, warn};
use maxmind::{Data, ProcessedDb};
use serde_derive::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, ErrorKind, Read, Write},
    path::PathBuf,
    time::Instant,
};
use tar::Archive;
use tokio::{signal, time};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub db: Db,
    pub interface: String,
    pub source_countries: FxHashSet<String>,
    pub source_asn: FxHashSet<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            db: Default::default(),
            interface: "enp1s0".to_string(),
            source_countries: Default::default(),
            source_asn: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Db {
    pub maxmind_key: String,
    pub refresh_interval: i64,
    pub path: String,
}

impl Default for Db {
    fn default() -> Self {
        Self {
            maxmind_key: "".to_string(),
            refresh_interval: 86400,
            path: "/tmp/geofw".to_string(),
        }
    }
}

fn read_config(path: &str) -> Result<Config, String> {
    match File::open(path) {
        Ok(mut f) => {
            let mut contents = vec![];
            f.read_to_end(&mut contents).map_err(|e| e.to_string())?;
            serde_json::from_slice(&contents).map_err(|e| e.to_string())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let def: Config = Default::default();
            match File::create(path) {
                Ok(mut f) => {
                    let json = serde_json::to_string_pretty(&def)
                        .expect("error in marshalling config to json");
                    if let Err(e) = f.write_all(json.as_bytes()) {
                        warn!("error in writing default config to disk: {}", e);
                    }
                }
                Err(e) => warn!("error in writing config to {}: {}", path, e),
            }
            Ok(def)
        }
        Err(e) => Err(format!("permission denied reading {}: {}", path, e)),
    }
}

fn fetch_geoip_db(config: &Config, db_type: MaxmindDbType) -> Result<ProcessedDb, String> {
    let mut unpack_path = PathBuf::new();
    unpack_path.push(&config.db.path);
    unpack_path.push(format!("{}.mmdb", db_type));

    let url = format!("https://download.maxmind.com/app/geoip_download?edition_id={}&license_key={}&suffix=tar.gz", db_type, config.db.maxmind_key);

    info!("path = {:?} fetching db from = {}", unpack_path, url);

    let response = ureq::get(&url).call();

    match response {
        Ok(v) if v.status() != 200 => {
            warn!("response from maxmind is not 200 = {}", v.status());
        }
        Ok(resp) => {
            let reader = resp.into_reader();
            let reader = BufReader::new(reader);
            let tar = GzDecoder::new(reader);
            let mut archive = Archive::new(tar);
            let entries = archive
                .entries()
                .map_err(|e| format!("error in listing files in the archive: {}", e))?;

            let db_entry = entries
                .into_iter()
                .filter_map(|e| e.ok())
                .filter_map(|entry| {
                    let Ok(path) = entry.path() else {
                        return None;
                    };
                    if path.extension().is_none_or(|x| x != "mmdb") {
                        return None;
                    }
                    Some(entry)
                })
                .next();

            let Some(mut db_entry) = db_entry else {
                return Err("error in finding mmdb file in the tarball".to_string());
            };

            db_entry.unpack(&unpack_path).map_err(|e| e.to_string())?;
        }
        Err(e) => {
            warn!("error in fetching db from maxmind: {}", e);
        }
    };

    let db = maxmind::MaxmindDb::from_file(&unpack_path.to_string_lossy())?;

    match db_type {
        MaxmindDbType::Country => Ok(db.consume(|data| -> bool {
            let Some(Data::Map(country)) = data.get("country".as_bytes()) else {
                return false;
            };
            let Some(iso_code) = country.get("iso_code".as_bytes()) else {
                return false;
            };

            config.source_countries.contains(&iso_code.to_string())
        })),
        MaxmindDbType::Asn => Ok(db.consume(|data| -> bool {
            let Some(Data::U32(asn)) = data.get("autonomous_system_number".as_bytes()) else {
                return false;
            };

            config.source_asn.contains(asn)
        })),
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

                match update_geoip_map(&config, &mut ebpf, MaxmindDbType::Country, "BLOCKED_COUNTRY") {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("error in updating map {} = {}", MaxmindDbType::Country, e);
                    }
                }

                match update_geoip_map(&config, &mut ebpf, MaxmindDbType::Asn, "BLOCKED_ASN") {
                    Ok(_) => (),
                    Err(e) => {
                        warn!("error in updating map {} = {}", MaxmindDbType::Asn, e);
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
    db_type: MaxmindDbType,
    map_name: &str,
) -> Result<(), String> {
    info!("updating maps db_type = {db_type} map_name = {map_name}");

    let mut map = Array::try_from(ebpf.map_mut(map_name).expect("error in getting map"))
        .expect("error in processing map");

    let result = fetch_geoip_db(config, db_type)?;

    let t = Instant::now();
    for (i, v) in result.db.into_iter().enumerate() {
        map.set(i as u32, v, 0).map_err(|e| e.to_string())?;
    }

    info!(
        "updated map = {} record_size = {} node_count = {} est_size = {} time_taken = {:?}",
        map_name,
        result.record_size,
        result.node_count,
        result.record_size as u64 * result.node_count as u64,
        t.elapsed()
    );

    let mut map: HashMap<&mut MapData, u8, u32> = HashMap::try_from(
        ebpf.map_mut("PARAMETERS")
            .expect("error in getting parameter map"),
    )
    .expect("error in processing parameter map");

    match db_type {
        MaxmindDbType::Country => {
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
        MaxmindDbType::Asn => {
            map.insert(ProgramParameters::AsnNodeCount as u8, result.node_count, 0)
                .expect("error in writing country node count to map");
            map.insert(
                ProgramParameters::AsnRecordSize as u8,
                result.record_size as u32,
                0,
            )
            .expect("error in writing country record size to map");
        }
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
