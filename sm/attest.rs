use core::mem::{size_of, zeroed};
use core::slice;

use crate::bindings::*;
use util::ctypes::*;

/* This will walk the entire vaddr space in the enclave, validating
linear at-most-once paddr mappings, and then hashing valid pages */
unsafe fn validate_and_hash_epm(
    hash_ctx: *mut hash_ctx,
    level: c_int,
    tb: *mut pte_t,
    vaddr: usize,
    mut contiguous: c_int,
    encl: *mut enclave,
    runtime_max_seen: *mut usize,
    user_max_seen: *mut usize,
) -> c_int {
    let encl = &mut *encl;

    //TODO check for failures
    let idx = get_enclave_region_index(encl, enclave_region_type_REGION_EPM) as usize;
    let epm_start = pmp_region_get_addr(encl.regions[idx].pmp_rid);
    let epm_size = pmp_region_get_size(encl.regions[idx].pmp_rid) as usize;
    let idx = get_enclave_region_index(encl, enclave_region_type_REGION_UTM) as usize;
    let utm_start = pmp_region_get_addr(encl.regions[idx].pmp_rid);
    let utm_size = pmp_region_get_size(encl.regions[idx].pmp_rid) as usize;

    let num_ptes = RISCV_PGSIZE as usize / size_of::<pte_t>();
    let ptes = slice::from_raw_parts_mut(tb, num_ptes);

    /* iterate over PTEs */
    for (i, walk) in ptes.iter_mut().enumerate() {
        if *walk == 0 {
            contiguous = 0;
            continue;
        }
        let phys_addr = (*walk >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

        /* Check for blatently invalid mappings */
        let map_in_epm = phys_addr >= epm_start && phys_addr < epm_start + epm_size;
        let map_in_utm = phys_addr >= utm_start && phys_addr < utm_start + utm_size;

        /* EPM may map anything, UTM may not map pgtables */
        if !map_in_epm && (!map_in_utm || level != 1) {
            return -1;
        }

        const PG_MASK: usize = RISCV_PGLEVEL_MASK as usize;
        const PG_HIBIT: usize = RISCV_PGTABLE_HIGHEST_BIT as usize;
        const PG_TOP: i32 = RISCV_PGLEVEL_TOP as i32;

        /* propagate the highest bit of the VA */
        let vpn = if level == PG_TOP && (i & PG_HIBIT != 0) {
            ((!0usize << RISCV_PGLEVEL_BITS) | (i & PG_MASK))
        } else {
            ((vaddr << RISCV_PGLEVEL_BITS) | (i & PG_MASK))
        };

        let va_start: usize = vpn << RISCV_PGSHIFT;

        /* include the first virtual address of a contiguous range */
        if level == 1 && contiguous == 0 {
            hash_extend(
                hash_ctx,
                &va_start as *const usize as *const c_void,
                size_of::<usize>(),
            );
            //printm("VA hashed: 0x%lx\n", va_start);
            contiguous = 1;
        }

        if level == 1 {
            /*
             * This is where we enforce the at-most-one-mapping property.
             * To make our lives easier, we also require a 'linear' mapping
             * (for each of the user and runtime spaces independently).
             *
             * That is: Given V1->P1 and V2->P2:
             *
             * V1 < V2  ==> P1 < P2  (Only for within a given space)
             *
             * V1 != V2 ==> P1 != P2
             *
             * We also validate that all utm vaddrs -> utm paddrs
             */
            let in_runtime = ((phys_addr >= encl.pa_params.runtime_base)
                && (phys_addr < encl.pa_params.user_base));
            let in_user =
                (phys_addr >= encl.pa_params.user_base) && (phys_addr < encl.pa_params.free_base);

            /* Validate U bit */
            if in_user && *walk & (PTE_U as usize) == 0 {
                return -1;
            }

            /* If the vaddr is in UTM, the paddr must be in UTM */
            if va_start >= encl.params.untrusted_ptr
                && va_start < (encl.params.untrusted_ptr + encl.params.untrusted_size)
                && !map_in_utm
            {
                return -1;
            }

            /* Do linear mapping validation */
            if in_runtime {
                if phys_addr <= *runtime_max_seen {
                    return -1;
                } else {
                    *runtime_max_seen = phys_addr;
                }
            } else if in_user {
                if phys_addr <= *user_max_seen {
                    return -1;
                } else {
                    *user_max_seen = phys_addr;
                }
            } else if map_in_utm {
                // we checked this above, its OK
            } else {
                //printm("BAD GENERIC MAP %x %x %x\n", in_runtime, in_user, map_in_utm);
                return -1;
            }

            /* Page is valid, add it to the hash */

            /* if PTE is leaf, extend hash for the page */
            hash_extend_page(hash_ctx, phys_addr as *mut c_void);

        //printm("PAGE hashed: 0x%lx (pa: 0x%lx)\n", vpn << RISCV_PGSHIFT, phys_addr);
        } else {
            /* otherwise, recurse on a lower level */
            contiguous = validate_and_hash_epm(
                hash_ctx,
                level - 1,
                phys_addr as *mut usize,
                vpn,
                contiguous,
                encl,
                runtime_max_seen,
                user_max_seen,
            );
            if contiguous == -1 {
                /*printm(
                    "BAD MAP: %lx->%lx epm %x %lx uer %x %lx\n",
                    va_start,
                    phys_addr,
                    //in_runtime,
                    0,
                    encl.pa_params.runtime_base,
                    0,
                    //in_user,
                    encl.pa_params.user_base,
                );*/
                return -1;
            }
        }
    }

    return contiguous;
}

#[no_mangle]
pub unsafe extern "C" fn validate_and_hash_enclave(enclave: *mut enclave) -> enclave_ret_code {
    let enclave = &mut *enclave;
    let ptlevel = RISCV_PGLEVEL_TOP as i32;

    let mut hash_ctx = zeroed();
    hash_init(&mut hash_ctx);

    // hash the runtime parameters
    hash_extend(
        &mut hash_ctx,
        &enclave.params as *const runtime_va_params_t as *const c_void,
        size_of::<runtime_va_params_t>(),
    );

    let mut runtime_max_seen = 0;
    let mut user_max_seen = 0;

    // hash the epm contents including the virtual addresses
    let valid = validate_and_hash_epm(
        &mut hash_ctx,
        ptlevel,
        (enclave.encl_satp << RISCV_PGSHIFT) as *mut pte_t,
        0,
        0,
        enclave,
        &mut runtime_max_seen,
        &mut user_max_seen,
    );

    if valid == -1 {
        return ENCLAVE_ILLEGAL_PTE as enclave_ret_code;
    }

    hash_finalize(enclave.hash.as_mut_ptr() as *mut c_void, &mut hash_ctx);

    return ENCLAVE_SUCCESS as enclave_ret_code;
}
