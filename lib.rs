#![feature(lang_items)]
#![no_std]


pub use sm;

extern {
    fn poweroff(retval: i32) -> !;
}

use core::panic::PanicInfo;
#[panic_handler]
pub extern fn panic_impl(info: &PanicInfo) -> ! {
    if let Some(msg) = info.payload().downcast_ref::<&str>() {
        util::print!("{}", msg);
    }

    unsafe {
        poweroff(-1);
    }
}
 
#[lang = "eh_personality"]
extern fn eh_personality() {}
