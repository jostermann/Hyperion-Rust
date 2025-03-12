use std::arch::x86_64::*;
use std::ffi::c_void;

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn all_bits_set_256_avx2(p_256: *const c_void) -> bool {
    // Invert the contents of p_256
    // Check if all bits of not(p_256) are set to 0 (test if not(p_256) and set1_epi8 == 0)
    // Returns 1, if all bits in p_256 are set, returns 0 if any bit in p_256 is not set
    let test_vector: __m256i = _mm256_loadu_si256(p_256 as *const __m256i);
    let all_ones: __m256i = _mm256_set1_epi8(-1);
    _mm256_testc_si256(test_vector, all_ones) == 1
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn get_index_first_set_bit_256_avx2(p_256: *const c_void) -> i32 {
    _mm_prefetch::<_MM_HINT_T0>(p_256 as *const i8);
    // Load p_256 and create an all-zero-vector
    // Compare p_256 and the all-zero-vector
    // Yields a mask that is 0 every time, a byte is 1 in p_256
    // Inverting the mask returns a mask that is 1 every time a byte is 1 in p_256
    let test_vector: __m256i = _mm256_loadu_si256(p_256 as *const __m256i);
    let all_zero: __m256i = _mm256_setzero_si256();
    let compare_zero: __m256i = _mm256_cmpeq_epi8(test_vector, all_zero);
    let bitmask: i32 = !_mm256_movemask_epi8(compare_zero);
    if bitmask == 0 {
        return -1;
    }

    let byte_index = (bitmask as u32).trailing_zeros() as usize;
    let byte = *(p_256 as *const u8).add(byte_index);
    let bit_pos = byte.trailing_zeros() as i32;
    ((byte_index as i32) * 8) + bit_pos
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn get_index_first_set_bit_256_avx2_2(p_256: *const c_void) -> Option<i32> {
    _mm_prefetch::<_MM_HINT_T0>(p_256 as *const i8);
    // Load p_256 and create an all-zero-vector
    // Compare p_256 and the all-zero-vector
    // Yields a mask that is 0 every time, a byte is 1 in p_256
    // Inverting the mask returns a mask that is 1 every time a byte is 1 in p_256
    let test_vector: __m256i = _mm256_loadu_si256(p_256 as *const __m256i);
    let all_zero: __m256i = _mm256_setzero_si256();
    let compare_zero: __m256i = _mm256_cmpeq_epi8(test_vector, all_zero);
    let bitmask: i32 = !_mm256_movemask_epi8(compare_zero);
    if bitmask == 0 {
        return None;
    }

    let byte_index = bitmask.trailing_zeros() as usize + 1;
    let byte = *(p_256 as *const i32).add((byte_index - 1) / 4);
    let bit_pos = byte + ((byte_index as i32 - 1) * 8);
    let t = bit_pos.trailing_zeros() as i32;
    Some(bit_pos.trailing_zeros() as i32)
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn sorted_insert_256_avx2(a: u16, p_256: *const u16) -> i32 {
    // Load p_256 and create a vector containing all a's value
    // Comparison of both vectors yields a bitmask containing the 16 bit index
    // divide index by two to get the 8 bit index
    let test_vector: __m256i = _mm256_loadu_si256(p_256 as *const __m256i);
    let insert_vector: __m256i = _mm256_set1_epi16(a as i16);
    let compare_insert: __m256i = _mm256_cmpgt_epi16(test_vector, insert_vector);
    let bitmask: i32 = _mm256_movemask_epi8(compare_insert);
    if bitmask == 0 {
        return -1;
    }
    // _mm_tzcnt_32 <=> __builtin_ffs(...) - 1
    _mm_tzcnt_32(bitmask as u32) / 2
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn sorted_insert_256_avx2_2(a: u16, p_256: *const u16) -> Option<usize> {
    // Load p_256 and create a vector containing all a's value
    // Comparison of both vectors yields a bitmask containing the 16 bit index
    // divide index by two to get the 8 bit index
    let test_vector: __m256i = _mm256_loadu_si256(p_256 as *const __m256i);
    let insert_vector: __m256i = _mm256_set1_epi16(a as i16);
    let compare_insert: __m256i = _mm256_cmpgt_epi16(test_vector, insert_vector);
    let bitmask: i32 = _mm256_movemask_epi8(compare_insert);
    if bitmask == 0 {
        return None;
    }
    // _mm_tzcnt_32 <=> __builtin_ffs(...) - 1
    Some((_mm_tzcnt_32(bitmask as u32) / 2) as usize)
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn index_a_in_b_256(a: i16, p_b256: *const c_void) -> i32 {
    let test_vector: __m256i = _mm256_lddqu_si256(p_b256 as *const __m256i);
    let test_value: __m256i = _mm256_set1_epi16(a);
    let compare_vector: __m256i = _mm256_cmpeq_epi16(test_value, test_vector);
    let bitmask: i32 = _mm256_movemask_epi8(compare_vector);
    if bitmask == 0 {
        return -1;
    };
    _mm_tzcnt_32(bitmask as u32) / 2
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn a_in_b_256_avx2(a: u16, p_b256: *const u16) -> i32 {
    (index_a_in_b_256(a as i16, p_b256 as *const c_void) != -1) as i32
}
