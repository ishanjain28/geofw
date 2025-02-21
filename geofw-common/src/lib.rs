#![no_std]

use core::fmt::{Display, Formatter, Result as FmtResult};

pub enum ProgramParameters {
    CountryNodeCount = 1,
    CountryRecordSize = 2,
    AsnNodeCount = 3,
    AsnRecordSize = 4,
}

// Block Marker should be larger than the size of binary tree size
// For 24bit record sizes, this'll be packed into 3 bits
// so either we make it different based on record size
// or since for this projet, I am only working with 24 bit dbs
// the value is set to 0x00ffffff
pub const BLOCK_MARKER: u32 = 0x00ffffff;

#[derive(Copy, Clone)]
pub enum MaxmindDbType {
    Country,
    Asn,
}

impl Display for MaxmindDbType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let val = match self {
            MaxmindDbType::Country => "GeoLite2-Country",
            MaxmindDbType::Asn => "GeoLite2-ASN",
        };

        write!(f, "{val}")
    }
}


