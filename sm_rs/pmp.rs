use core::mem::forget;

use crate::bindings::*;
use util::ctypes::*;

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
    pub fn reserve(base: usize, size: usize, prio: Priority, allow_overlap: bool) -> Result<Self, c_int> {
        let region = unsafe {
            let mut region = 0;
            let err = pmp_region_init_atomic(base, size as u64, prio as u32, &mut region, allow_overlap as c_int);
            if err != 0 {
                return Err(err);
            }
            region
        };

        Ok(Self {
            region,
            should_free: true,
        })
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

    #[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_free_region_idx() {
        unsafe {
            region_def_bitmap = 0x20;
            assert_eq!(get_free_region_idx(), 0);
            region_def_bitmap = 0x3f;
            assert_eq!(get_free_region_idx(), 6);

            // tear down
            region_def_bitmap = 0x0;
        }
    }

    #[test]
    fn test_get_free_reg_idx() {
        unsafe {
            reg_bitmap = 0x20;
            assert_eq!(get_free_reg_idx(), 0);
            reg_bitmap = 0x3f;
            assert_eq!(get_free_reg_idx(), 6);

            // tear down
            reg_bitmap = 0x0;
        }
    }
}
