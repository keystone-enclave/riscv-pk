use core::mem::forget;

use util::ctypes::*;
use crate::bindings::*;

pub enum Priority {
    Any = pmp_priority_PMP_PRI_ANY as isize,
    Bottom = pmp_priority_PMP_PRI_BOTTOM as isize,
}

pub struct PmpRegion {
    region: c_int,
}

impl PmpRegion {
    pub fn reserve(base: usize, size: usize, prio: Priority) -> Result<Self, c_int> {
        let region = unsafe {
            let mut region = 0;
            let err = pmp_region_init_atomic(base, size as u64, prio as u32, &mut region, 0);
            if err != 0 {
                return Err(err);
            }
            region
        };

        Ok(Self { region })
    }

    pub fn leak(self) -> c_int {
        let out = self.region;
        forget(self);
        out
    }

    pub fn set_global(&mut self, prop: u8) -> Result<(), c_int> {
        let err = unsafe { pmp_set_global(self.region, prop) };
        if err == 0 {
            Ok(())
        } else {
            Err(err)
        }
    }
}

impl Drop for PmpRegion {
    fn drop(&mut self) {
        unsafe {
            pmp_region_free_atomic(self.region);
        }
    }
}

