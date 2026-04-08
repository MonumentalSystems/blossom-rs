//! Internal xdelta3 FFI bindings (VCDIFF binary delta encoding).

mod binding {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]

    include!(concat!(env!("OUT_DIR"), "/xdelta3_bindings.rs"));
}

/// Encode a binary delta from `src` (original) to `input` (new).
pub fn encode(input: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let input_len = input.len() as std::ffi::c_uint;
    let src_len = src.len() as std::ffi::c_uint;
    let estimated_out_len = (input_len + src_len) * 2;
    let mut avail_output: std::ffi::c_uint = 0;
    let mut output = Vec::with_capacity(estimated_out_len as usize);

    let result = unsafe {
        binding::xd3_encode_memory(
            input.as_ptr(),
            input_len,
            src.as_ptr(),
            src_len,
            output.as_mut_ptr(),
            &mut avail_output,
            estimated_out_len,
            0,
        )
    };

    if result == 0 {
        unsafe { output.set_len(avail_output as usize) };
        Some(output)
    } else {
        None
    }
}

/// Decode a binary delta. `src` is the original, `input` is the delta.
pub fn decode(input: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let input_len = input.len() as std::ffi::c_uint;
    let src_len = src.len() as std::ffi::c_uint;
    let estimated_out_len = (input_len + src_len) * 2;
    let mut avail_output: std::ffi::c_uint = 0;
    let mut output = Vec::with_capacity(estimated_out_len as usize);

    let result = unsafe {
        binding::xd3_decode_memory(
            input.as_ptr(),
            input_len,
            src.as_ptr(),
            src_len,
            output.as_mut_ptr(),
            &mut avail_output,
            estimated_out_len,
            0,
        )
    };

    if result == 0 {
        unsafe { output.set_len(avail_output as usize) };
        Some(output)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let src = b"hello world, this is the original data";
        let new = b"hello world, this is the modified data";
        let delta = encode(new, src).expect("encode failed");
        let recovered = decode(&delta, src).expect("decode failed");
        assert_eq!(recovered, new);
    }
}
