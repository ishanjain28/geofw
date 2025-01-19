use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    fs::File,
    io::Read,
    net::Ipv4Addr,
};

const METADATA_SECTION_START: &[u8] = &[
    0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d,
];

pub struct MaxmindDB {
    metadata: Metadata,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct Metadata {
    node_count: u32,
    record_size: u16,
    binary_tree_section_start: usize,
    data_section_start: usize,
    metadata_section_start: usize,
}

#[derive(Debug, PartialEq, Clone)]
enum Data {
    String(String),
    Double(f64),
    Bytes(Vec<u8>),
    U16(u16),
    U32(u32),
    Map(HashMap<String, Data>),
    I32(i32),
    U64(u64),
    U128(u128),
    Array(Vec<Data>),
    DataCache,
    End,
    Boolean(bool),
    Float(f32),
}

impl Debug for MaxmindDB {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_fmt(format_args!("{:?}", self.metadata))
    }
}

impl MaxmindDB {
    pub fn new(path: &str) -> Self {
        let mut data = vec![];
        {
            let mut file = File::open(path).expect("error in opening file");
            file.read_to_end(&mut data)
                .expect("error in reading contents of file");
        }

        let position = data
            .windows(METADATA_SECTION_START.len())
            .rev()
            .position(|x| x == METADATA_SECTION_START)
            .unwrap();
        let metadata_start = data.len() - position;
        let mut db = Self {
            metadata: Metadata::default(),
            data: data.to_vec(), // TODO: Change this ?
        };

        let m = db.read_metadata(metadata_start);
        println!("metadata = {:?}", m);
        let Data::U16(record_size) = *m.get("record_size").unwrap() else {
            unreachable!()
        };
        let Data::U32(node_count) = *m.get("node_count").unwrap() else {
            unreachable!()
        };
        db.metadata = Metadata {
            binary_tree_section_start: 0,
            data_section_start: ((record_size as usize * 2) / 8) * node_count as usize + 16,
            metadata_section_start: metadata_start,
            record_size,
            node_count,
        };

        db
    }

    fn read_metadata(&self, metadata_start: usize) -> HashMap<String, Data> {
        let (Data::Map(map), _) = self.read_data(metadata_start) else {
            unreachable!()
        };
        map
    }

    pub fn read_binary_search_tree(&self) {
        // Only support 28bit format for now
        assert_eq!(self.metadata.record_size, 28);

        let node_size = self.metadata.record_size as usize * 2 / 8;
        let mut node = 96;
        let mut ip = Ipv4Addr::new(139, 84, 164, 110).to_bits();

        let mut i = 0;
        while i < 32 && node < self.metadata.node_count {
            let bit = ip & 0x80000000;
            ip <<= 1;

            let n = &self.data[node as usize * node_size..(node as usize * node_size) + node_size];
            node = if bit == 0 {
                u32::from_be_bytes([n[3] & 0b1111_0000, n[0], n[1], n[2]])
            } else {
                u32::from_be_bytes([n[3] & 0b0000_1111, n[4], n[5], n[6]])
            };

            i += 1;
        }

        if node == self.metadata.node_count {
            println!("not found!");
        } else {
            let data_section_offset = node - self.metadata.node_count;
            let data = self
                .read_data(self.metadata.data_section_start + data_section_offset as usize - 16);

            println!("{:?}", data);
        }
    }

    fn read_data(&self, read_offset: usize) -> (Data, usize) {
        // println!("read offset: {}", read_offset);
        let data = &self.data[read_offset..];
        let (data_type, length, read) = Self::read_data_meta(data);

        // println!("{} {} {}", data_type, length, read);

        match data_type {
            1 => {
                // println!("read = {:?}", read + read_offset);
                // let data = &data[read..];
                let s = (data[0] >> 3) & 0x3;
                let v = data[0] & 0b0000_0111;

                let pointer = match s {
                    0 => u32::from_be_bytes([0, 0, v, data[1]]),
                    1 => u32::from_be_bytes([0, v, data[1], data[2]]) + 2048,
                    2 => u32::from_be_bytes([v, data[1], data[2], data[3]]) + 526336,
                    3 => u32::from_be_bytes([data[1], data[2], data[3], data[4]]),
                    _ => unreachable!(),
                };

                let (data, _) = self.read_data(self.metadata.data_section_start + pointer as usize);
                (data, s as usize + 1 + 1)
            }
            2 => {
                let value = &data[read..read + length];

                (
                    Data::String(String::from_utf8_lossy(value).to_string()),
                    read + length,
                )
            }
            3 => {
                assert_eq!(length, 8);
                let s = &data[read..read + length];
                let num = f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);

                (Data::Double(num), read + length)
            }
            4 => {
                todo!("reached data field???");
            }
            5 => {
                let slice = &data[read..read + length];
                let number = match *slice {
                    [] => 0,
                    [a] => a as u16,
                    [a, b] => (a as u16) << 8 | b as u16,
                    _ => unreachable!(),
                };

                (Data::U16(number), read + length)
            }
            6 => {
                let slice = &data[read..read + length];
                let number = match *slice {
                    [] => 0,
                    [a] => a as u32,
                    [a, b] => (a as u32) << 8 | b as u32,
                    [a, b, c] => (a as u32) << 16 | (b as u32) << 8 | c as u32,
                    [a, b, c, d] => {
                        (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32
                    }
                    _ => unreachable!(),
                };

                (Data::U32(number), read + length)
            }
            7 => {
                let mut map = HashMap::with_capacity(length);
                // length is number of elements
                let mut length = length;
                let mut read = read;

                while length > 0 {
                    let (key, r) = self.read_data(read_offset + read);
                    read += r;
                    let (value, r) = self.read_data(read_offset + read);
                    read += r;

                    let Data::String(key) = key else {
                        unreachable!()
                    };

                    map.insert(key, value);
                    length -= 1;
                }

                (Data::Map(map), read)
            }
            8 => {
                let slice = &data[read..read + length];
                let number = match *slice {
                    [] => 0,
                    [a] => a as i32,
                    [a, b] => (a as i32) << 8 | b as i32,
                    [a, b, c] => (a as i32) << 16 | (b as i32) << 8 | c as i32,
                    [a, b, c, d] => {
                        (a as i32) << 24 | (b as i32) << 16 | (c as i32) << 8 | d as i32
                    }
                    _ => unreachable!(),
                };

                (Data::I32(number), read + length)
            }
            9 => {
                let slice = &data[read..read + length];
                let number = slice.iter().enumerate().fold(0, |acc, (i, &byte)| {
                    acc | ((byte as u64) << (8 * (slice.len() - i - 1)))
                });

                (Data::U64(number), read + length)
            }
            10 => {
                let slice = &data[read..read + length];
                let number = slice.iter().enumerate().fold(0, |acc, (i, &byte)| {
                    acc | ((byte as u128) << (8 * (slice.len() - i - 1)))
                });

                (Data::U128(number), read + length)
            }
            11 => {
                let mut read = read;
                let mut out = vec![];
                let mut length = length;

                while length > 0 {
                    let (value, r) = self.read_data(read_offset + read);
                    read += r;
                    length -= 1;
                    out.push(value);
                }

                (Data::Array(out), read)
            }
            12 => {
                todo!("reached data cache container");
            }
            13 => (Data::End, read_offset),
            14 => {
                todo!("reached boolean");
            }
            15 => {
                assert_eq!(length, 4);
                let s = &data[read..read + length];
                let num = f32::from_be_bytes([s[0], s[1], s[2], s[3]]);

                (Data::Float(num), read + length)
            }
            _ => unreachable!(),
        }
    }

    fn read_data_meta(data: &[u8]) -> (u8, usize, usize) {
        let mut read = 0;
        let data_type = if data[0] >> 5 == 0 {
            read += 1;
            data[1] + 7
        } else {
            data[0] >> 5
        };

        let length = data[0] & 0b000_11111;

        let (length, r) = match length {
            0..29 => (length as usize, 1),
            29 => (29 + data[1] as usize, 2),
            30 => (285 + data[1] as usize + data[2] as usize, 3),
            31 => (
                65821 + data[1] as usize + data[2] as usize + data[3] as usize,
                4,
            ),
            _ => unreachable!(),
        };

        (data_type, length, read + r)
    }
}
