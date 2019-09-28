#![feature(lang_items)]
#![no_std]


pub use sm;


use core::panic::PanicInfo;
#[panic_handler]
pub extern fn panic_impl(_info: &PanicInfo) -> ! {
    loop {}
}
 
#[lang = "eh_personality"]
extern fn eh_personality() {}

#[no_mangle]
extern fn abort() -> ! {
    loop {}
}
