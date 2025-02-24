use std::arch::x86_64::{_mm_prefetch, _MM_HINT_T2};
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::memorymanager::internals::simd_avx2::*;
use crate::memorymanager::internals::simd_sse4_1::*;

pub(crate) fn apply_simd<T, R>(field: &[T], simd_func: unsafe fn(*const c_void) -> R) -> R {
    let field_ptr: *const c_void = field.as_ptr() as *const c_void;
    unsafe { simd_func(field_ptr) }
}

pub(crate) fn apply_sorted_insert<T>(num: u16, field: &[T]) -> Option<usize> {
    let field_ptr: *const u16 = field.as_ptr() as *const u16;
    unsafe { sorted_insert_256_2(num, field_ptr) }
}

pub(crate) fn apply_index_search(num: u16, field: *const u32) -> i32 {
    let field_ptr: *const c_void = field as *const c_void;
    unsafe { index_a_in_b_256(num as i16, field_ptr) }
}

static mut PSEUDORAND: AtomicUsize = AtomicUsize::new(0);

#[inline(always)]
pub(crate) unsafe fn prefetch(addr: *const u8) {
    // Prefetch the cache line containing addr into L3 or higher
    _mm_prefetch::<_MM_HINT_T2>(addr as *const i8);
}

unsafe fn all_bits_set_256_fallback(p_256: *const c_void) -> bool {
    let p_ptr: *const u64 = p_256 as *const u64;
    (*p_ptr != 0) && (*p_ptr.add(1) != 0) && (*p_ptr.add(2) != 0) && (*p_ptr.add(3) != 0)
}

pub(crate) unsafe fn all_bits_set_256(p_256: *const c_void) -> bool {
    if p_256.is_null() {
        return false;
    }

    if is_x86_feature_detected!("avx2") {
        all_bits_set_256_avx2(p_256)
    } else if is_x86_feature_detected!("sse4.1") {
        all_bits_set_256_sse41(p_256)
    } else {
        all_bits_set_256_fallback(p_256)
    }
}

pub(crate) unsafe fn all_bits_set_4096(p_4096: *const c_void) -> bool {
    for i in 0..(4096 / 256) {
        prefetch((p_4096 as *const u8).add((i + 1) * 32));
        if !all_bits_set_256(p_4096.add(i * 32)) {
            return false;
        }
    }
    all_bits_set_256(p_4096.add(480))
}

unsafe fn get_index_first_set_bit_256_fallback(p_256: *const c_void) -> i32 {
    // Iterate over all 64-bit words in p_256
    // If a 64-bit word contains 1, return the index of the 64-bit word + offset within the word
    let p_iter_64: *const u64 = p_256 as *const u64;

    for i in 0..4 {
        let val: u64 = p_iter_64.add(i).read_unaligned();
        if val != 0 {
            return (i * 64) as i32 + val.trailing_zeros() as i32;
        }
    }
    -1
}

unsafe fn get_index_first_set_bit_256_fallback_2(p_256: *const c_void) -> Option<i32> {
    // Iterate over all 64-bit words in p_256
    // If a 64-bit word contains 1, return the index of the 64-bit word + offset within the word
    let p_iter_64: *const u64 = p_256 as *const u64;

    for i in 0..4 {
        let val: u64 = p_iter_64.add(i).read_unaligned();
        if val != 0 {
            return Some((i * 64) as i32 + val.trailing_zeros() as i32);
        }
    }
    None
}

pub(crate) unsafe fn get_index_first_set_bit_256(p_256: *const c_void) -> i32 {
    if p_256.is_null() {
        return -1;
    }

    if is_x86_feature_detected!("avx2") {
        get_index_first_set_bit_256_avx2(p_256)
    } else if is_x86_feature_detected!("sse4.1") {
        get_index_first_set_bit_256_sse41(p_256)
    } else {
        get_index_first_set_bit_256_fallback(p_256)
    }
}

pub(crate) unsafe fn get_index_first_set_bit_256_2(p_256: *const c_void) -> Option<i32> {
    if p_256.is_null() {
        return None;
    }

    if is_x86_feature_detected!("avx2") {
        get_index_first_set_bit_256_avx2_2(p_256)
    } else if is_x86_feature_detected!("sse4.1") {
        get_index_first_set_bit_256_sse41_2(p_256)
    } else {
        get_index_first_set_bit_256_fallback_2(p_256)
    }
}

pub(crate) unsafe fn get_index_first_set_bit_4096(p_4096: *const c_void) -> i32 {
    const BLOCKS_SIZE: usize = 32;
    const BITS_PER_BLOCK: usize = 256;
    const BLOCKS: usize = 4096 / BITS_PER_BLOCK;
    let offset: usize = PSEUDORAND.load(Ordering::Relaxed);

    for i in 0..BLOCKS {
        let block = (i + offset) & (BLOCKS - 1);
        let res: i32 = get_index_first_set_bit_256(p_4096.add(block * BLOCKS_SIZE));
        if res != -1 {
            PSEUDORAND.store(block, Ordering::Relaxed);
            return (block * BITS_PER_BLOCK) as i32 + res;
        }
    }
    PSEUDORAND.store(0, Ordering::Relaxed);
    -1
}

pub(crate) unsafe fn get_index_first_set_bit_4096_2(p_4096: *const c_void) -> Option<i32> {
    const BLOCKS_SIZE: usize = 32;
    const BITS_PER_BLOCK: usize = 256;
    const BLOCKS: usize = 4096 / BITS_PER_BLOCK;
    let offset: usize = PSEUDORAND.load(Ordering::Relaxed);

    for i in 0..BLOCKS {
        let block = (i + offset) & (BLOCKS - 1);
        let res: Option<i32> = get_index_first_set_bit_256_2(p_4096.add(block * BLOCKS_SIZE));
        if res.is_some() {
            PSEUDORAND.store(block, Ordering::Relaxed);
            return Some((block * BITS_PER_BLOCK) as i32 + res.unwrap());
        }
    }
    PSEUDORAND.store(0, Ordering::Relaxed);
    None
}

pub(crate) unsafe fn count_set_bits(p_4096: *const c_void) -> i32 {
    let p = p_4096 as *const u8;
    let count = 4096 / 64;

    (0..count)
        .map(|i| {
            if i + 1 < count {
                // If a next word exists, prefetch it into the cache
                prefetch(p.add((i + 1) * 8));
            }
            // Load the current 8-Byte word and count the set bits
            (p.add(i * 8) as *const u64).read_unaligned().count_ones() as i32
        })
        .sum() // Sum up all counts of set bits of all 8-byte words
}

unsafe fn sorted_insert_256_fallback(a: u16, p_256: *const u16) -> i32 {
    (0..16).find(|&i| a <= *p_256.add(i)).map_or(-1, |i| if a != *p_256.add(i) { i as i32 } else { -1 })
}

pub(crate) unsafe fn sorted_insert_256(a: u16, b: *const u16) -> i32 {
    if b.is_null() {
        return -1;
    }

    if is_x86_feature_detected!("avx2") {
        sorted_insert_256_avx2(a, b)
    } else if is_x86_feature_detected!("sse4.1") {
        sorted_insert_256_sse41(a, b)
    } else {
        sorted_insert_256_fallback(a, b)
    }
}

unsafe fn sorted_insert_256_fallback_2(a: u16, p_256: *const u16) -> Option<usize> {
    (0..16).find(|&i| a <= *p_256.add(i)).map_or(None, |i| if a != *p_256.add(i) { Some(i) } else { None })
}

pub(crate) unsafe fn sorted_insert_256_2(a: u16, b: *const u16) -> Option<usize> {
    if b.is_null() {
        return None;
    }

    if is_x86_feature_detected!("avx2") {
        sorted_insert_256_avx2_2(a, b)
    } else if is_x86_feature_detected!("sse4.1") {
        sorted_insert_256_sse41_2(a, b)
    } else {
        sorted_insert_256_fallback_2(a, b)
    }
}

unsafe fn a_in_b_256_fallback(a: u16, p_b256: *const u16) -> i32 {
    (0..16).any(|i| *p_b256.add(i) == a) as i32
}

pub(crate) unsafe fn a_in_b_256(a: u16, p_b256: *const u16) -> i32 {
    if p_b256.is_null() {
        return -1;
    }

    if is_x86_feature_detected!("avx2") {
        a_in_b_256_avx2(a, p_b256)
    } else if is_x86_feature_detected!("sse4.1") {
        a_in_b_256_sse41(a, p_b256)
    } else {
        a_in_b_256_fallback(a, p_b256)
    }
}

#[cfg(test)]
mod ops_test {
    use std::alloc::{alloc, dealloc, Layout};

    use crate::memorymanager::internals::simd_common::*;

    #[test]
    fn test_all_bits_set_256() {
        unsafe {
            let layout = Layout::from_size_align(32, 32).unwrap();
            let ptr = alloc(layout);

            for i in 0..32 {
                ptr.add(i).write(0xFF);
            }

            assert!(all_bits_set_256_avx2(ptr as *const c_void));
            assert_eq!(all_bits_set_256_sse41(ptr as *const c_void), true);
            assert_eq!(all_bits_set_256_fallback(ptr as *const c_void), true);

            let ptr2 = alloc(layout);

            for i in 0..32 {
                ptr.add(i).write(0x00);
            }

            assert_eq!(all_bits_set_256_avx2(ptr2 as *const c_void), false);
            assert_eq!(all_bits_set_256_sse41(ptr2 as *const c_void), false);
            assert_eq!(all_bits_set_256_fallback(ptr2 as *const c_void), false);

            dealloc(ptr, layout);
            dealloc(ptr2, layout);
        }
    }

    #[test]
    fn test_all_bits_set_4096() {
        unsafe {
            let layout = Layout::from_size_align(512, 512).unwrap();
            let ptr = alloc(layout);
            if ptr.is_null() {
                panic!("Memory allocation failed");
            }

            for i in 0..512 {
                ptr.add(i).write(0xFF);
            }

            assert_eq!(all_bits_set_4096(ptr as *const c_void), true);

            let ptr2 = alloc(layout);

            for i in 0..512 {
                ptr.add(i).write(0x00);
            }

            assert_eq!(all_bits_set_4096(ptr2 as *const c_void), false);

            dealloc(ptr, layout);
            dealloc(ptr2, layout);
        }
    }

    #[test]
    fn test_get_index_first_set_bit_256() {
        unsafe {
            let layout = Layout::from_size_align(32, 32).unwrap();
            let ptr = alloc(layout);
            for i in 0..32 {
                ptr.add(i).write(0x00);
            }

            assert_eq!(get_index_first_set_bit_256_avx2(ptr as *const c_void), -1);
            assert_eq!(get_index_first_set_bit_256_sse41(ptr as *const c_void), -1);
            assert_eq!(get_index_first_set_bit_256_fallback(ptr as *const c_void), -1);

            for i in 1..30 {
                ptr.add(i).write(2);
                assert_eq!(get_index_first_set_bit_256_avx2(ptr as *const c_void), 1 + (i as i32) * 8);
                assert_eq!(get_index_first_set_bit_256_sse41(ptr as *const c_void), 1 + (i as i32) * 8);
                assert_eq!(get_index_first_set_bit_256_fallback(ptr as *const c_void), 1 + (i as i32) * 8);
                ptr.add(i).write(0x00);
            }

            ptr.add(24).write(0xFF); // add 24 Bytes -> Bit at index 192 set
            assert_eq!(get_index_first_set_bit_256_avx2(ptr as *const c_void), 192);
            assert_eq!(get_index_first_set_bit_256_sse41(ptr as *const c_void), 192);
            assert_eq!(get_index_first_set_bit_256_fallback(ptr as *const c_void), 192);
            ptr.add(24).write(0x00);

            let offset_byte = ptr.add(24); // add 193 Bits / 24 Bytes and 1 Bit -> Bit at index 193 set
            *offset_byte |= 1 << 1;
            assert_eq!(get_index_first_set_bit_256_avx2(ptr as *const c_void), 193);
            assert_eq!(get_index_first_set_bit_256_sse41(ptr as *const c_void), 193);
            assert_eq!(get_index_first_set_bit_256_fallback(ptr as *const c_void), 193);
            dealloc(ptr, layout);
        }
    }

    #[test]
    fn test_get_index_first_set_bit_4096() {
        unsafe {
            let layout = Layout::from_size_align(512, 8).unwrap();
            let ptr = alloc(layout);
            for i in 0..512 {
                ptr.add(i).write(0x00);
            }
            assert_eq!(get_index_first_set_bit_4096(ptr as *const c_void), -1);
            ptr.write(0x00);
            ptr.add(100).write(0xFF); // add 100 Bytes ->  Bit at index 800 set
            assert_eq!(get_index_first_set_bit_4096(ptr as *const c_void), 800);
            dealloc(ptr, layout);
        }
    }

    #[test]
    fn test_count_set_bits() {
        unsafe {
            let layout = Layout::from_size_align(512, 8).unwrap();
            let ptr = alloc(layout);
            for i in 0..512 {
                ptr.add(i).write(0x00);
            }
            assert_eq!(count_set_bits(ptr as *const c_void), 0);
            ptr.add(10).write(0xFF);
            ptr.add(20).write(0xFF);
            ptr.add(30).write(0xFF);
            assert_eq!(count_set_bits(ptr as *const c_void), 24);
            dealloc(ptr, layout);
        }
    }

    #[test]
    fn test_sorted_insert() {
        unsafe {
            let layout = Layout::from_size_align(32, 16).unwrap();
            let ptr = alloc(layout) as *mut u16;
            for i in 0..16 {
                ptr.add(i).write(i as u16 * 2);
            }
            assert_eq!(sorted_insert_256_avx2(5, ptr as *const u16), 3);
            assert_eq!(sorted_insert_256_sse41(5, ptr as *const u16), 3);
            assert_eq!(sorted_insert_256_fallback(5, ptr as *const u16), 3);
            assert_eq!(sorted_insert_256_avx2(29, ptr as *const u16), 15);
            assert_eq!(sorted_insert_256_sse41(29, ptr as *const u16), 15);
            assert_eq!(sorted_insert_256_fallback(29, ptr as *const u16), 15);
            assert_eq!(sorted_insert_256_avx2(40, ptr as *const u16), -1);
            assert_eq!(sorted_insert_256_sse41(40, ptr as *const u16), -1);
            assert_eq!(sorted_insert_256_fallback(40, ptr as *const u16), -1);
            dealloc(ptr as *mut u8, layout);
        }
    }

    #[test]
    fn test_simd_256_a_in_b() {
        unsafe {
            let layout = Layout::from_size_align(32, 16).unwrap();
            let ptr = alloc(layout) as *mut u16;
            for i in 0..16 {
                ptr.add(i).write(i as u16);
                assert_eq!(index_a_in_b_256(i as i16, ptr as *const c_void), i as i32);
            }
            assert_eq!(a_in_b_256_avx2(5, ptr as *const u16), 1);
            assert_eq!(a_in_b_256_sse41(5, ptr as *const u16), 1);
            assert_eq!(a_in_b_256_fallback(5, ptr as *const u16), 1);
            assert_eq!(a_in_b_256_avx2(20, ptr as *const u16), 0);
            assert_eq!(a_in_b_256_sse41(20, ptr as *const u16), 0);
            assert_eq!(a_in_b_256_fallback(20, ptr as *const u16), 0);
            dealloc(ptr as *mut u8, layout);
        }
    }
}
