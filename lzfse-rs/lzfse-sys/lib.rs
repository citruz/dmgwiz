extern crate libc;

use libc::{c_char, c_void, size_t};

extern "C" {
    pub fn lzfse_encode_buffer(
        dst_buffer: *mut c_char,
        dst_size: size_t,
        src_buffer: *const c_char,
        src_size: size_t,
        scratch_buffer: *mut c_void,
    ) -> size_t;

    pub fn lzfse_decode_scratch_size() -> size_t;

    pub fn lzfse_decode_buffer(
        dst_buffer: *mut c_char,
        dst_size: size_t,
        src_buffer: *const c_char,
        src_size: size_t,
        scratch_buffer: *mut c_void,
    ) -> size_t;
}
