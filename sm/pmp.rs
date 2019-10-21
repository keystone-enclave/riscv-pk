use core::mem::forget;

use util::ctypes::*;
use crate::bindings::*;

pub enum Priority {
    Any = pmp_priority_PMP_PRI_ANY as isize,
    Top = pmp_priority_PMP_PRI_TOP as isize,
    Bottom = pmp_priority_PMP_PRI_BOTTOM as isize,
}

pub struct PmpRegion {
    region: c_int,
    should_free: bool,
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

        Ok(Self { region, should_free: true })
    }

    pub unsafe fn wrap_id(region_id: c_int) -> Self {
        Self {
            region: region_id,
            should_free: false,
        }
    }

    pub unsafe fn own_id(region_id: c_int) -> Self {
        Self {
            region: region_id,
            should_free: true,
        }
    }

    pub fn leak(self) -> c_int {
        let out = self.region;
        forget(self);
        out
    }

    pub fn set_perm(&mut self, perm: u8) -> Result<(), c_int> {
        let err = unsafe { pmp_set(self.region, perm) };
        if err == 0 {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn unset_perm(&mut self) -> Result<(), c_int> {
        let err = unsafe { pmp_unset(self.region) };
        if err == 0 {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn set_global(&mut self, perm: u8) -> Result<(), c_int> {
        let err = unsafe { pmp_set_global(self.region, perm) };
        if err == 0 {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn unset_global(&mut self) -> Result<(), c_int> {
        let err = unsafe { pmp_unset_global(self.region) };
        if err == 0 {
            Ok(())
        } else {
            Err(err)
        }
    }

    pub fn addr(&self) -> usize {
        let addr = unsafe { pmp_region_get_addr(self.region) };
        assert!(addr != 0);
        addr
    }

    pub fn size(&self) -> usize {
        (unsafe { pmp_region_get_size(self.region) }) as usize
    }
}

impl Drop for PmpRegion {
    fn drop(&mut self) {
        if self.should_free {
            unsafe {
                pmp_region_free_atomic(self.region);
            }
        }
    }
}


pub fn detect_region_overlap(base: usize, size: usize) -> bool {
    1 == unsafe { pmp_detect_region_overlap_atomic(base, size) }
}

