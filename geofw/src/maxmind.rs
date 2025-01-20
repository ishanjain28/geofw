use fxhash::FxHashMap;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    fs::File,
    io::Read,
    net::IpAddr,
    ops::Range,
};

const METADATA_SECTION_START: &[u8] = &[
    0xab, 0xcd, 0xef, 0x4d, 0x61, 0x78, 0x4d, 0x69, 0x6e, 0x64, 0x2e, 0x63, 0x6f, 0x6d,
];

pub struct MaxmindDB {
    pub metadata: Metadata,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Metadata {
    node_count: u32,
    record_size: u16,
    pub data_section_start: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Data {
    String(Range<usize>),
    Double(f64),
    Bytes(Vec<u8>),
    U16(u16),
    U32(u32),
    Map(FxHashMap<String, Data>),
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
        let Data::U16(record_size) = *m.get("record_size").unwrap() else {
            unreachable!()
        };
        let Data::U32(node_count) = *m.get("node_count").unwrap() else {
            unreachable!()
        };

        db.metadata = Metadata {
            data_section_start: ((record_size as usize * 2) / 8) * node_count as usize + 16,
            record_size,
            node_count,
        };

        db
    }

    fn read_metadata(&self, metadata_start: usize) -> FxHashMap<String, Data> {
        let (Data::Map(map), _) = self.read_data(metadata_start) else {
            unreachable!()
        };
        map
    }

    fn node_from_bytes(n: &[u8], bit: u128, record_size: u16) -> u32 {
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
            _ => unreachable!(),
        }
    }

    pub fn lookup(&self, addr: IpAddr) -> Option<Data> {
        let node_size = self.metadata.record_size as usize * 2 / 8;
        let mut node = 0;
        let mut ip = match addr {
            IpAddr::V4(a) => a.to_bits() as u128,
            IpAddr::V6(a) => a.to_bits(),
        };

        let mut i = 0;
        while i < 128 && node < self.metadata.node_count {
            let bit = ip & (1 << 127);
            ip <<= 1;

            let n = &self.data[node as usize * node_size..(node as usize * node_size) + node_size];
            node = Self::node_from_bytes(n, bit, self.metadata.record_size);
            i += 1;
        }

        if node == self.metadata.node_count {
            None
        } else {
            let data_section_offset = node - self.metadata.node_count;
            let (data, _) = self
                .read_data(self.metadata.data_section_start + data_section_offset as usize - 16);

            Some(data)
        }
    }

    pub fn read_binary_tree(&self, node: u32, position: usize) {
        let mut stack = vec![];
        let node_size = self.metadata.record_size as usize * 2 / 8;

        let mut count = 0;
        stack.push((node, position));

        while let Some((node, position)) = stack.pop() {
            let n = &self.data[node as usize * node_size..(node as usize * node_size) + node_size];
            let node_1 = Self::node_from_bytes(n, 0, self.metadata.record_size);
            let node_2 = Self::node_from_bytes(n, 1, self.metadata.record_size);

            if position < 128 && node_1 < self.metadata.node_count {
                stack.push((node_1, position + 1));
            }
            if position < 128 && node_2 < self.metadata.node_count {
                stack.push((node_2, position + 1));
            }

            if node_1 > self.metadata.node_count {
                let data_section_offset = node_1 - self.metadata.node_count;

                let data = self.read_data(
                    self.metadata.data_section_start + data_section_offset as usize - 16,
                );
                count += 1;
            }

            if node_2 > self.metadata.node_count {
                let data_section_offset = node_2 - self.metadata.node_count;
                let data = self.read_data(
                    self.metadata.data_section_start + data_section_offset as usize - 16,
                );

                count += 1;
            }
        }

        println!("count = {}", count);
    }

    fn read_data(&self, read_offset: usize) -> (Data, usize) {
        let data = &self.data[read_offset..];
        let (data_type, length, read) = Self::read_data_meta(data);

        match data_type {
            1 => self.follow_pointer(read_offset),
            2 => {
                // let value = String::from_utf8_lossy(&data[read..read + length]);
                (
                    Data::String(read_offset + read..read_offset + read + length),
                    read + length,
                )
            }
            3 => {
                assert_eq!(length, 8);

                (Self::read_float::<8>(data), read + length)
            }
            4 => {
                todo!("reached data field???");
            }
            5 => (self.read_u16(read_offset + read, length), read + length),
            6 => (self.read_u32(read_offset + read, length), read + length),
            7 => self.read_map(read_offset, read, length),
            8 => (self.read_i32(read_offset + read, length), read + length),
            9 => (self.read_u64(read_offset + read, length), read + length),
            10 => (self.read_u128(read_offset + read, length), read + length),
            11 => self.read_array(read_offset, read, length),
            12 => {
                todo!("reached data cache container");
            }
            13 => (Data::End, read_offset + read),
            14 => (Data::Boolean(length == 1), read),
            15 => {
                assert_eq!(length, 4);

                (Self::read_float::<4>(data), read + length)
            }
            _ => unreachable!(),
        }
    }

    fn read_map(&self, offset: usize, read: usize, length: usize) -> (Data, usize) {
        let mut map = FxHashMap::with_capacity_and_hasher(length, Default::default());
        // length is number of elements
        let mut length = length;
        let mut read = read;

        while length > 0 {
            let (key, r) = self.read_data(offset + read);
            read += r;
            let (value, r) = self.read_data(offset + read);
            read += r;

            let Data::String(key) = key else {
                unreachable!()
            };
            let key = String::from_utf8_lossy(&self.data[key]);

            map.insert(key.to_string(), value);
            length -= 1;
        }

        (Data::Map(map), read)
    }

    fn read_array(&self, offset: usize, read: usize, length: usize) -> (Data, usize) {
        let mut read = read;
        let mut out = vec![];
        let mut length = length;

        while length > 0 {
            let (value, r) = self.read_data(offset + read);
            read += r;
            length -= 1;
            out.push(value);
        }

        (Data::Array(out), read)
    }

    fn read_u16(&self, offset: usize, length: usize) -> Data {
        let slice = &self.data[offset..offset + length];
        let number = match *slice {
            [] => 0,
            [a] => a as u16,
            [a, b] => (a as u16) << 8 | b as u16,
            _ => unreachable!(),
        };

        Data::U16(number)
    }

    fn read_i32(&self, offset: usize, length: usize) -> Data {
        let slice = &self.data[offset..offset + length];
        let number = match *slice {
            [] => 0,
            [a] => a as i32,
            [a, b] => (a as i32) << 8 | b as i32,
            [a, b, c] => (a as i32) << 16 | (b as i32) << 8 | c as i32,
            [a, b, c, d] => (a as i32) << 24 | (b as i32) << 16 | (c as i32) << 8 | d as i32,
            _ => unreachable!(),
        };

        Data::I32(number)
    }

    fn read_u32(&self, offset: usize, length: usize) -> Data {
        let slice = &self.data[offset..offset + length];
        let number = match *slice {
            [] => 0,
            [a] => a as u32,
            [a, b] => (a as u32) << 8 | b as u32,
            [a, b, c] => (a as u32) << 16 | (b as u32) << 8 | c as u32,
            [a, b, c, d] => (a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | d as u32,
            _ => unreachable!(),
        };

        Data::U32(number)
    }

    fn read_u64(&self, offset: usize, length: usize) -> Data {
        let slice = &self.data[offset..offset + length];
        let number = slice.iter().enumerate().fold(0, |acc, (i, &byte)| {
            acc | ((byte as u64) << (8 * (slice.len() - i - 1)))
        });

        Data::U64(number)
    }

    fn read_u128(&self, offset: usize, length: usize) -> Data {
        let slice = &self.data[offset..offset + length];
        let number = slice.iter().enumerate().fold(0, |acc, (i, &byte)| {
            acc | ((byte as u128) << (8 * (slice.len() - i - 1)))
        });

        Data::U128(number)
    }

    fn follow_pointer(&self, offset: usize) -> (Data, usize) {
        let data = &self.data[offset..];
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

    fn read_float<const T: usize>(d: &[u8]) -> Data {
        match T {
            4 => {
                let num = f32::from_be_bytes([d[0], d[1], d[2], d[3]]);
                Data::Float(num)
            }
            8 => {
                let num = f64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
                Data::Double(num)
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
