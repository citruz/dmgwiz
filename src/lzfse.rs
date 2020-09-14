use byteorder::{ReadBytesExt, LE};
use std::{
    cmp,
    collections::VecDeque,
    io::{self, Read},
};

/// Wrapper around the lzfse library which implements the `Read` trait to access decompressed data
pub struct Decoder<R> {
    input: R,
    buf: Option<VecDeque<u8>>,
}

impl<R: Read> Decoder<R> {
    pub fn new(input: R) -> Self {
        Self { input, buf: None }
    }

    fn fill_buff(&mut self) -> io::Result<()> {
        let next_block = decode_block(&mut self.input)?;
        self.buf = next_block.map(Into::into);
        Ok(())
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.buf.is_none() {
            self.fill_buff()?;
        }

        let source = match &mut self.buf {
            Some(b) => b,
            None => return Ok(0),
        };

        let read_len = cmp::min(source.len(), buf.len());
        source
            .drain(..read_len)
            .zip(buf.iter_mut())
            .for_each(|(src, dst)| *dst = src);

        Ok(read_len)
    }
}

const MAGIC_ENDOFSTREAM: [u8; 4] = *b"bvx$";
const MAGIC_UNCOMPRESSED: [u8; 4] = *b"bvx-";
const MAGIC_LZFSE_V1: [u8; 4] = *b"bvx1";
const MAGIC_LZFSE_V2: [u8; 4] = *b"bvx2";
const MAGIC_LZVN: [u8; 4] = *b"bvxn";

const MAGIC_SIZE: usize = 4;
const HEADER_SIZE_UNCOMPRESSED: usize = 4;
const HEADER_SIZE_LZFSE_V1: usize = 768;
const HEADER_SIZE_LZFSE_V2: usize = 28;
const HEADER_SIZE_LZVN: usize = 8;

#[derive(Debug)]
struct Header {
    raw: Vec<u8>,
    n_raw_bytes: u32,
    n_payload_bytes: u32,
}

impl Header {
    fn uncompressed<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut raw = vec![0; HEADER_SIZE_UNCOMPRESSED];
        input.read_exact(&mut raw)?;

        let n_raw_bytes = parse_u32(&raw)?;

        Ok(Self {
            raw,
            n_raw_bytes,
            n_payload_bytes: n_raw_bytes,
        })
    }

    fn lzfse_v1<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut raw = vec![0; HEADER_SIZE_LZFSE_V1];
        input.read_exact(&mut raw)?;

        let n_raw_bytes = parse_u32(&raw)?;
        let n_literal_payload_bytes = parse_u32(&raw[20..])?;
        let n_lmd_payload_bytes = parse_u32(&raw[24..])?;
        let n_payload_bytes = n_literal_payload_bytes + n_lmd_payload_bytes;

        Ok(Self {
            raw,
            n_raw_bytes,
            n_payload_bytes,
        })
    }

    fn lzfse_v2<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut raw = vec![0; HEADER_SIZE_LZFSE_V2];
        input.read_exact(&mut raw)?;

        let n_raw_bytes = parse_u32(&raw)?;

        let packed1 = parse_u64(&raw[4..])?;
        let packed2 = parse_u64(&raw[12..])?;

        let n_literal_payload_bytes = parse_packed_field(packed1, 20, 20);
        let n_lmd_payload_bytes = parse_packed_field(packed2, 40, 20);
        let header_size = parse_u32(&raw[20..])?;
        let remaining_header_bytes = header_size - (MAGIC_SIZE + HEADER_SIZE_LZFSE_V2) as u32;

        let n_payload_bytes =
            remaining_header_bytes + n_literal_payload_bytes + n_lmd_payload_bytes;

        Ok(Self {
            raw,
            n_raw_bytes,
            n_payload_bytes,
        })
    }

    fn lzvn<R: Read>(input: &mut R) -> io::Result<Self> {
        let mut raw = vec![0; HEADER_SIZE_LZVN];
        input.read_exact(&mut raw)?;

        let n_raw_bytes = parse_u32(&raw)?;
        let n_payload_bytes = parse_u32(&raw[4..])?;

        Ok(Self {
            raw,
            n_raw_bytes,
            n_payload_bytes,
        })
    }

    fn size(&self) -> usize {
        self.raw.len()
    }
}

fn parse_u32(mut bytes: &[u8]) -> io::Result<u32> {
    bytes.read_u32::<LE>()
}

fn parse_u64(mut bytes: &[u8]) -> io::Result<u64> {
    bytes.read_u64::<LE>()
}

fn parse_packed_field(packed: u64, offset: usize, nbits: usize) -> u32 {
    let mask = (1 << nbits) - 1;
    ((packed >> offset) & mask) as u32
}

fn decode_block<R: Read>(input: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut magic = [0; 4];
    input.read_exact(&mut magic)?;

    let header = match magic {
        MAGIC_UNCOMPRESSED => Header::uncompressed(input)?,
        MAGIC_LZFSE_V1 => Header::lzfse_v1(input)?,
        MAGIC_LZFSE_V2 => Header::lzfse_v2(input)?,
        MAGIC_LZVN => Header::lzvn(input)?,
        MAGIC_ENDOFSTREAM => return Ok(None),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid block magic",
            ))
        }
    };

    // Read the full block (header + payload) into a buffer that can be passed
    // to `decode_buffer`. Also append a dummy ENDOFSTREAM header to ensure
    // we don't get an error in the success case.
    let header_size = MAGIC_SIZE + header.size();
    let payload_size = header.n_payload_bytes as usize;
    let mut src = vec![0; header_size + payload_size + 4];
    src[..MAGIC_SIZE].copy_from_slice(&magic);
    src[MAGIC_SIZE..header_size].copy_from_slice(&header.raw);
    input.read_exact(&mut src[header_size..][..payload_size])?;
    src[header_size + payload_size..].copy_from_slice(&MAGIC_ENDOFSTREAM);

    let mut dst = vec![0; header.n_raw_bytes as usize];

    match lzfse::decode_buffer(&src, &mut dst) {
        Err(lzfse::Error::BufferTooSmall) => (),
        Err(lzfse::Error::CompressFailed) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid input data",
            ))
        }
        Ok(_) => unreachable!("we always fill the whole out_buf"),
    }

    Ok(Some(dst))
}
