extern crate libc;
extern crate lzfse_sys as ffi;

use libc::size_t;

#[derive(PartialEq, Debug)]
pub enum Error {
    BufferTooSmall,
}

pub fn decode_buffer(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let out_size = unsafe {
        ffi::lzfse_decode_buffer(
            output.as_ptr() as *mut _,
            output.len() as size_t,
            input.as_ptr() as *const _,
            input.len() as size_t,
            0 as *mut _,
        ) as usize
    };

    if out_size == output.len() {
        return Err(Error::BufferTooSmall);
    } else {
        return Ok(out_size);
    }
}
