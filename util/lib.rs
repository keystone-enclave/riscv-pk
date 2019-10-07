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


use core::fmt;

pub struct LogWriter;

impl fmt::Write for LogWriter {
    #[inline(never)]
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        extern {
            fn mcall_console_putchar(ch: u8) -> u32;
        }
        for c in s.bytes() {
            unsafe {
                mcall_console_putchar(c);
            }
        }
        Ok(())
    }
} 

#[macro_export]
macro_rules! print {
    ($($tok:tt)*) => {{
        use ::core::fmt::Write;
        write!($crate::LogWriter, $($tok)*).unwrap();
    }};
}

#[macro_export]
macro_rules! println {
    ($($tok:tt)*) => {{
        use $crate::print;
        print!($($tok)*); print!("\n");
    }};
}
