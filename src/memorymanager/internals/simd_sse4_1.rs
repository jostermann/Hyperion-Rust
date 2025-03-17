use std::arch::x86_64::{
    __m128i, _mm_cmpeq_epi16, _mm_cmpgt_epi16, _mm_loadu_si128, _mm_movemask_epi8, _mm_set1_epi16, _mm_test_all_ones, _mm_testz_si128, _mm_tzcnt_32,
    _mm_tzcnt_64,
};
use std::ffi::c_void;

/// Returns if all bits are set in the referenced memory region.
#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn all_bits_set_256_sse41(p_256: *const c_void) -> bool {
    // Checks p_256 in two separate halves
    // First test_all returns 1, if all bits in first half are set
    // Second test_all returns 1, if all bits in second half are set
    // Returns 1, if both halves contain only set bits
    let first_half: i32 = _mm_test_all_ones(_mm_loadu_si128(p_256 as *const __m128i));
    let second_half: i32 = _mm_test_all_ones(_mm_loadu_si128((p_256 as *const __m128i).add(1)));
    (first_half & second_half) == 1
}

#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn get_index_first_set_bit_256_sse41(p_256: *const c_void) -> i32 {
    // Iterate over all 64-bit words in p_256
    // If a 64-bit word contains 1, return the index of the 64-bit word + offset within the word
    let p_iter_64: *const u64 = p_256 as *const u64;

    for i in 0..4 {
        let val: u64 = p_iter_64.add(i).read_unaligned();
        if val != 0 {
            return (i * 64) as i32 + _mm_tzcnt_64(val) as i32;
        }
    }
    -1
}

/// Returns the index of the first set bit int the referenced memory region.
#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn get_index_first_set_bit_256_sse41_2(p_256: *const c_void) -> Option<i32> {
    // Iterate over all 64-bit words in p_256
    // If a 64-bit word contains 1, return the index of the 64-bit word + offset within the word
    let p_iter_64: *const u64 = p_256 as *const u64;

    for i in 0..4 {
        let val: u64 = p_iter_64.add(i).read_unaligned();
        if val != 0 {
            return Some((i * 64) as i32 + _mm_tzcnt_64(val) as i32);
        }
    }
    None
}

/// Returns the index of where to insert `a` into `p_256` in a sorted manner.
#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn sorted_insert_256_sse41(a: u16, p_256: *const u16) -> i32 {
    let test_vector: __m128i = _mm_loadu_si128(p_256 as *const __m128i);
    let test_vector2: __m128i = _mm_loadu_si128((p_256 as *const __m128i).add(1));
    let test_value: __m128i = _mm_set1_epi16(a as i16);
    let bitmask1: i32 = _mm_movemask_epi8(_mm_cmpgt_epi16(test_vector, test_value));
    if bitmask1 != 0 {
        return _mm_tzcnt_32(bitmask1 as u32) >> 1;
    };
    let bitmask2 = _mm_movemask_epi8(_mm_cmpgt_epi16(test_vector2, test_value));
    if bitmask2 != 0 {
        return 8 + (_mm_tzcnt_32(bitmask2 as u32) >> 1);
    }
    -1
}

/// Returns the index of where to insert `a` into `p_256` in a sorted manner.
#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn sorted_insert_256_sse41_2(a: u16, p_256: *const u16) -> Option<usize> {
    let test_vector: __m128i = _mm_loadu_si128(p_256 as *const __m128i);
    let test_vector2: __m128i = _mm_loadu_si128((p_256 as *const __m128i).add(1));
    let test_value: __m128i = _mm_set1_epi16(a as i16);
    let bitmask1: i32 = _mm_movemask_epi8(_mm_cmpgt_epi16(test_vector, test_value));
    if bitmask1 != 0 {
        return Some((_mm_tzcnt_32(bitmask1 as u32) >> 1) as usize);
    };
    let bitmask2 = _mm_movemask_epi8(_mm_cmpgt_epi16(test_vector2, test_value));
    if bitmask2 != 0 {
        return Some((8 + (_mm_tzcnt_32(bitmask2 as u32) >> 1)) as usize);
    }
    None
}

/// Returns if `a` is contained in `p_256`.
#[target_feature(enable = "sse4.1")]
pub(crate) unsafe fn a_in_b_256_sse41(a: u16, p_b256: *const u16) -> i32 {
    let test_vector: __m128i = _mm_loadu_si128(p_b256 as *const __m128i);
    let test_value: __m128i = _mm_set1_epi16(a as i16);
    let compare_vector: __m128i = _mm_cmpeq_epi16(test_value, test_vector);

    if _mm_testz_si128(compare_vector, compare_vector) == 1 {
        let x: __m128i = _mm_cmpeq_epi16(test_value, _mm_loadu_si128(p_b256.add(8) as *const __m128i));
        return (_mm_testz_si128(x, x) == 0) as i32;
    }
    1
}
