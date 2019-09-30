#![no_std]

#[allow(non_camel_case_types)]
pub mod ctypes {
    pub type c_char = u8;
    pub type c_uchar = u8;
    pub type c_schar = i8;

    pub type c_short = i16;
    pub type c_ushort = u16;

    pub type c_int = i32;
    pub type c_uint = u32;

    pub type c_long = isize;
    pub type c_ulong = usize;

    pub type c_longlong = i64;
    pub type c_ulonglong = u64;

    pub type c_float = f32;
    pub type c_double = f64;

    pub use core::ffi::c_void;
}
pub use ctypes::*;
