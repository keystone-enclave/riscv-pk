#![feature(lang_items, custom_test_frameworks, panic_info_message)]

#![no_std]

pub mod bitfield;

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
    #[cfg(target_os = "none")]
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

    #[cfg(target_os = "linux")]
    fn write_str(&mut self, s: &str) -> Result<(), fmt::Error> {
        extern {
            fn putchar(ch: u8) -> c_int;
        }

        for c in s.bytes() {
            let ret = unsafe {
                putchar(c)
            };
            if ret != (c as c_int) {
                return Err(fmt::Error)
            }
            if c == b'\n' {
                log_flush();
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub fn log_flush() { }
#[cfg(target_os = "linux")]
pub fn log_flush() {
    extern {
        static mut stdout: *mut c_void;
        fn fflush(file: *mut c_void) -> c_int;
    }
    
    unsafe {
        fflush(stdout);
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



extern {
    fn poweroff(retval: i32) -> !;
}

use core::panic::PanicInfo;
#[panic_handler]
pub extern fn panic_impl(info: &PanicInfo) -> ! {
    println!("");

    if let Some(loc) = info.location() {
        println!("Panicked at `{}` L{}:{}!", loc.file(), loc.line(), loc.column());
    } else {
        println!("Panicked!");
    }
    if let Some(msg) = info.message() {
        print!("    ");
        let _ = fmt::write(&mut LogWriter, *msg);
    }

    println!("");
    log_flush();
    unsafe {
        poweroff(-1);
    }
}
 
#[lang = "eh_personality"]
extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[no_mangle]
extern fn abort() -> ! {
    loop {}
}

#[cfg_attr(target_os = "linux", link(name = "c"))]
#[cfg_attr(target_os = "linux", link(name = "m"))]
#[cfg_attr(target_os = "linux", link(name = "rt"))]
#[cfg_attr(target_os = "linux", link(name = "pthread"))]
extern {}
