use core::mem::{size_of, zeroed};
use core::slice;

use util::ctypes::*;
use crate::bindings::*;

pub const SIGNATURE_SIZE: usize = crate::bindings::SIGNATURE_SIZE as usize;
pub const PRIVKEY_SIZE: usize = crate::bindings::PRIVATE_KEY_SIZE as usize;
pub const PUBKEY_SIZE: usize = crate::bindings::PUBLIC_KEY_SIZE as usize;
pub const HASH_SIZE: usize = crate::bindings::MDSIZE as usize;

pub struct Hasher {
    _inner: hash_ctx
}

impl Hasher {
    pub fn new() -> Self {
        let mut out = Self {
            _inner: unsafe { zeroed() }
        };
        unsafe {
            sha3_init(&mut out._inner, HASH_SIZE as i32);
        }
        out
    }

    pub fn hash<T: Copy>(&mut self, data: &T) {
        unsafe {
            sha3_update(&mut self._inner, data as *const T as *const c_void, size_of::<T>());
        }
    }

    pub unsafe fn hash_page(&mut self, data: *const c_void) {
        sha3_update(&mut self._inner, data, RISCV_PGSIZE as usize);
    }

    pub fn finalize(&mut self, out: &mut [u8; HASH_SIZE]) {
        unsafe {
            sha3_final(out.as_mut_ptr() as *mut c_void, &mut self._inner);
        }
    }
}



pub fn _sign<T: Copy>(sig_out: &mut [u8; SIGNATURE_SIZE], data: &T, pubkey: &[u8], privkey: &[u8]) {
    let data_bytes_ptr = data as *const T as *const u8;
    let data_bytes = unsafe {
        slice::from_raw_parts(data_bytes_ptr, size_of::<T>())
    };
    sign_bytes(sig_out, data_bytes, pubkey, privkey);
}

pub fn sign_bytes(sig_out: &mut [u8; SIGNATURE_SIZE], data: &[u8], pubkey: &[u8], privkey: &[u8]) {
    assert_eq!(pubkey.len(), PUBKEY_SIZE, "Attempted to sign with bad pubkey size!");
    assert_eq!(privkey.len(), PRIVKEY_SIZE, "Attempted to sign with bad privkey size!");

    unsafe {
        ed25519_sign(sig_out.as_mut_ptr(), data.as_ptr(), data.len(), pubkey.as_ptr(), privkey.as_ptr());
    }
}

pub fn kdf (
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> i32 {
    unsafe {
        hkdf_sha3_512(salt.as_ptr(), salt.len() as i32,
                      ikm.as_ptr(), ikm.len() as i32,
                      info.as_ptr(), info.len() as i32,
                      okm.as_mut_ptr(), okm.len() as i32)
    }
}


#[cfg(test)]
mod test {
    use super::*;

    fn check_hash(hash: &[u8], s: &'static str) {
        let chunk_iter = s.as_bytes()
            .chunks(2)
            .map(|c| core::str::from_utf8(c).unwrap())
            .map(|s| u8::from_str_radix(s, 16).unwrap());

        for (expected, byte) in chunk_iter.zip(hash.iter()) {
            assert_eq!(*byte, expected);
        }
    }

    #[test]
    fn test_hasher_empty() {
        let mut out = [0u8; HASH_SIZE];

        let mut hasher = Hasher::new();
        let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
        hasher.finalize(&mut out);

        check_hash(&out, expected);
    }

    #[test]
    fn test_hasher_strbuf() {
        let mut out = [0u8; HASH_SIZE];

        let mut hasher = Hasher::new();
        let expected = "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976";
        hasher.hash(b"hello");
        hasher.finalize(&mut out);

        check_hash(&out, expected);
    }
}
