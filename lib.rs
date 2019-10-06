#![feature(lang_items)]
#![no_std]


pub use sm;

extern {
    fn mcall_console_putchar(ch: u8) -> u32;
    fn poweroff(retval: i32) -> !;
}

use core::panic::PanicInfo;
#[panic_handler]
pub extern fn panic_impl(info: &PanicInfo) -> ! {
    if let Some(msg) = info.payload().downcast_ref::<&str>() {
        for c in msg.bytes() {
            unsafe {
                mcall_console_putchar(c);
            }
        }
    }

    unsafe {
        poweroff(-1);
    }
}
 
#[lang = "eh_personality"]
extern fn eh_personality() {}
