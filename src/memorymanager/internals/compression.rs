use crate::memorymanager::api::{Arena, AtomicMemoryPointer, ARENA_COMPRESSION};
use crate::memorymanager::components::arena::ArenaInner;
use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS, BIN_ELEMENTS_DEFLATED};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::{Superbin, SUPERBIN_ARRAY_MAXSIZE};
use crate::memorymanager::internals::allocator::AllocatedBy::{Heap, Mmap};
use crate::memorymanager::internals::allocator::{allocate_heap, allocate_mmap, auto_allocate_memory, auto_free_memory};
use crate::memorymanager::internals::simd_common::a_in_b_256;
use crate::memorymanager::internals::simd_common::apply_simd;
use crate::memorymanager::internals::system_information::get_memory_stats;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use libc::{c_char, c_int, memcpy, memset};
use lz4_sys::{LZ4_compress_fast, LZ4_decompress_safe};
use std::cmp::PartialEq;
use std::ffi::c_void;
use std::intrinsics::copy_nonoverlapping;
use std::ptr::{copy, null_mut};
use std::sync::atomic::Ordering::{Relaxed, Release};
use std::sync::atomic::{AtomicI32, AtomicI64};
use zstd_sys::{ZSTD_compress, ZSTD_decompress};

pub(crate) const SLIDING_WINDOW_SIZE: usize = 12;
/// Start deflating
pub(crate) const COMPRESSION_LIMIT_S0: f64 = 0.6;
/// lz4 fast-12
pub(crate) const COMPRESSION_LIMIT_S1: f64 = 0.7;
/// lz4 fast-1
pub(crate) const COMPRESSION_LIMIT_S2: f64 = 0.8;
/// zstd
pub(crate) const COMPRESSION_LIMIT_S3: f64 = 0.9;

pub(crate) const COMPRESSION_ATT_LZ4_0: usize = 9;
pub(crate) const COMPRESSION_ATT_LZ4_1: usize = 1;
pub(crate) const COMPRESSION_ATT_ZSTD: usize = 1;

#[derive(Copy, Clone, Default)]
pub(crate) struct CompressionSlidingWindow {
    metabin: u16,
    superbin: u16,
}

pub(crate) enum CompressionStrategy {
    None,
    Deflate,
    Lz4_0,
    Lz4_1,
    Zstd,
}

#[derive(Debug, PartialOrd, PartialEq, Copy, Clone)]
pub(crate) enum CompressionState {
    None = 0,
    Deflate = 1,
    Lz4 = 2,
    Zstd = 3,
}

impl CompressionState {
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Deflate,
            2 => Self::Lz4,
            3 => Self::Zstd,
            _ => {
                panic!("Use of undefined compression type")
            },
        }
    }
}

pub(crate) struct CompressedContainerHead {
    pub(crate) original_size: i32,
    pub(crate) compressed_size: i32,
    original_compression_state: CompressionState,
}

static ORIGINAL_COMPRESSED_SIZE: AtomicI64 = AtomicI64::new(0);
static ORIGINAL_DECOMPRESSED_SIZE: AtomicI64 = AtomicI64::new(0);
static COMPRESSED_BYTES: AtomicI64 = AtomicI64::new(0);
static DECOMPRESSED_BYTES: AtomicI64 = AtomicI64::new(0);
static COMPRESSED_TOTAL: AtomicI64 = AtomicI64::new(0);
static TRIMMED_CHUNKS: AtomicI32 = AtomicI32::new(0);

pub fn get_reset_original_compressed() -> i64 {
    let res = ORIGINAL_COMPRESSED_SIZE.load(Relaxed);
    ORIGINAL_COMPRESSED_SIZE.store(0, Relaxed);
    res
}

pub fn get_reset_original_decompressed() -> i64 {
    let res = ORIGINAL_DECOMPRESSED_SIZE.load(Relaxed);
    ORIGINAL_DECOMPRESSED_SIZE.store(0, Relaxed);
    res
}

pub fn get_reset_compressed_bytes() -> i64 {
    let res = COMPRESSED_BYTES.load(Relaxed);
    COMPRESSED_BYTES.store(0, Relaxed);
    res
}

pub fn get_reset_decompressed_bytes() -> i64 {
    let res = DECOMPRESSED_BYTES.load(Relaxed);
    DECOMPRESSED_BYTES.store(0, Relaxed);
    res
}

pub fn get_reset_trimmed_chunks() -> i32 {
    let res = TRIMMED_CHUNKS.load(Relaxed);
    TRIMMED_CHUNKS.store(0, Relaxed);
    res
}

pub fn get_compressed_total() -> i64 {
    COMPRESSED_TOTAL.load(Relaxed)
}

pub(crate) fn get_compression_strategy() -> CompressionStrategy {
    let sys_rate: f64 = get_memory_stats(false).read().sys_rate;

    if sys_rate > COMPRESSION_LIMIT_S3 {
        CompressionStrategy::Zstd
    } else if sys_rate > COMPRESSION_LIMIT_S2 {
        CompressionStrategy::Lz4_1
    } else if sys_rate > COMPRESSION_LIMIT_S1 {
        CompressionStrategy::Lz4_0
    } else if sys_rate > COMPRESSION_LIMIT_S0 {
        CompressionStrategy::Deflate
    } else {
        CompressionStrategy::None
    }
}

pub fn update_sliding_window(arena: &mut ArenaInner, new_superbin_id: u8, new_metabin_id: u16) {
    unsafe {
        copy(
            arena.sliding_window.as_mut_ptr().add(1) as *mut u8,
            arena.sliding_window.as_mut_ptr() as *mut u8,
            size_of::<CompressionSlidingWindow>() * (SLIDING_WINDOW_SIZE - 1),
        );
    }
    arena.sliding_window[SLIDING_WINDOW_SIZE - 1].metabin = new_metabin_id;
    arena.sliding_window[SLIDING_WINDOW_SIZE - 1].superbin = new_superbin_id as u16;
}

pub fn check_superbin_iterator(arena: &mut ArenaInner, superbin: &mut Superbin) {
    if superbin.header.metabins_compression_iterator_id() == 0 {
        arena.compression_iterator += 1;
        if arena.compression_iterator as usize >= SUPERBIN_ARRAY_MAXSIZE {
            arena.compression_iterator = 1;
        }
    }
}

pub fn get_metabin_iterator(superbin: &mut Superbin) -> u32 {
    let current_value: u16 = superbin.header.metabins_compression_iterator_id();
    superbin.header.set_metabins_compression_iterator_id(current_value + 1);

    let mut iterator_id = superbin.header.metabins_compression_iterator_id();

    if iterator_id >= superbin.header.metabins_initialized() {
        superbin.header.set_metabins_compression_iterator_id(0);
        iterator_id = 0;
    }
    iterator_id as u32
}

pub fn truncate_metabin_array(superbin: &mut Superbin) -> i32 {
    let mut truncated = 0i32;
    loop {
        let index = superbin.header.metabins_initialized() - 1;
        let metabin = superbin.metabins.get(index as usize).unwrap();

        if unsafe { a_in_b_256(metabin.id, superbin.metabin_ring.as_mut_ptr()) > 0 } {
            break;
        }

        for i in 0..BIN_ELEMENTS {
            if metabin.bins[i].chunks.is_notnull() {
                break;
            }
        }

        superbin.metabins.delete_metabin(index as usize);
        superbin.header.set_metabins_initialized(index);
        truncated += 1;

        if superbin.header.metabins_initialized() <= 1 {
            break;
        }
    }
    truncated
}

pub fn check_metabin_actions(superbin: *mut Superbin, metabin: &mut Metabin) -> bool {
    if metabin.id == unsafe { (*superbin).metabin_ring[0] } {
        return true;
    }
    if metabin.id == unsafe { (*superbin).header.metabins_initialized() - 1 } {
        return truncate_metabin_array(unsafe { superbin.as_mut().unwrap() }) == 0;
    }
    false
}

pub(crate) fn pdb_copy_chunk(bin: &mut Bin, size: usize, index: usize, target: &mut AtomicMemoryPointer, nci_iterator: &mut usize, nci: &mut [u16]) {
    unsafe {
        nci[*nci_iterator] = index as u16;
        memcpy(target.get().add(size * (*nci_iterator)), bin.chunks.get().add(size * index), size);
        *nci_iterator += 1;
    }
}

pub fn perform_bin_compression(arena: &mut ArenaInner, superbin: *mut Superbin, bin: *mut Bin, strategy: CompressionStrategy) {
    if unsafe { (*bin).header.compression_state() != CompressionState::None } {
        return;
    }

    let source_size = unsafe { (*superbin).header.size_of_bin() as usize * BIN_ELEMENTS };
    let destination_size = source_size - size_of::<CompressedContainerHead>();

    if destination_size >= ARENA_COMPRESSION {
        return;
    }

    if arena.compression_cache.is_null() {
        arena.compression_cache.store(unsafe { allocate_mmap(ARENA_COMPRESSION) });
    }

    let head = arena.compression_cache.get() as *mut CompressedContainerHead;
    unsafe {
        let target = (head as *mut u8).add(size_of::<CompressedContainerHead>());
        (*head).original_size = source_size as i32;
        (*head).original_compression_state = (*bin).header.compression_state();

        let new_compression_state;

        match strategy {
            CompressionStrategy::Lz4_0 => {
                (*head).compressed_size = LZ4_compress_fast(
                    (*bin).chunks.get() as *const c_char,
                    target as *mut c_char,
                    source_size as c_int,
                    destination_size as c_int,
                    COMPRESSION_ATT_LZ4_0 as c_int,
                ) as i32;
                new_compression_state = CompressionState::Lz4;
            },
            CompressionStrategy::Lz4_1 => {
                (*head).compressed_size = LZ4_compress_fast(
                    (*bin).chunks.get() as *const c_char,
                    target as *mut c_char,
                    source_size as c_int,
                    destination_size as c_int,
                    COMPRESSION_ATT_LZ4_1 as c_int,
                ) as i32;
                new_compression_state = CompressionState::Lz4;
            },
            CompressionStrategy::Zstd => {
                (*head).compressed_size =
                    ZSTD_compress(target as *mut c_void, destination_size, (*bin).chunks.get(), source_size, COMPRESSION_ATT_ZSTD as c_int) as i32;
                new_compression_state = CompressionState::Zstd;
            },
            _ => {
                new_compression_state = CompressionState::None;
                assert_eq!(1, 0);
            },
        }

        if 0 < (*head).compressed_size && (*head).compressed_size < (*head).original_size {
            (*head).compressed_size += size_of::<CompressedContainerHead>() as i32;
            COMPRESSED_BYTES.fetch_add((*head).original_size as i64 - (*head).compressed_size as i64, Relaxed);
            ORIGINAL_COMPRESSED_SIZE.fetch_add((*head).original_size as i64, Relaxed);
            assert!(auto_free_memory((*bin).chunks.get(), source_size, (*bin).header.allocated_by()));
            (*bin).chunks.store(allocate_mmap((*head).compressed_size as usize));
            (*bin).header.set_allocated_by(Mmap);
            assert!(!(*bin).chunks.is_null());
            copy_nonoverlapping(head as *mut u8, (*bin).chunks.get() as *mut u8, (*head).compressed_size as usize);
            (*bin).header.set_compression_state(new_compression_state);
        }
    }
}

pub(crate) fn perform_bin_deflation(bin: &mut Bin, size: usize) {
    let mut new_chunk_index: [u16; BIN_ELEMENTS_DEFLATED] = [u16::MAX; BIN_ELEMENTS_DEFLATED];
    let mut nci_iterator = 0;
    let mut new_mem = AtomicMemoryPointer::new();
    let new_allocation = unsafe { auto_allocate_memory(&mut new_mem, size * BIN_ELEMENTS_DEFLATED) };
    unsafe {
        memset(new_mem.get(), 0, size * BIN_ELEMENTS_DEFLATED);
    }

    for i in 0..BIN_ELEMENTS {
        if bin.chunk_usage_mask[i / 8] & (1 << (i % 8)) == 0 {
            pdb_copy_chunk(bin, size, i, &mut new_mem, &mut nci_iterator, &mut new_chunk_index);
        }
    }

    unsafe {
        auto_free_memory(bin.chunks.get(), BIN_ELEMENTS * size, bin.header.allocated_by());
    }
    bin.chunks.clone_from(&mut new_mem);
    bin.header.set_allocated_by(new_allocation);
    unsafe {
        memcpy(&mut bin.chunk_usage_mask as *mut u32 as *mut c_void, &mut new_chunk_index as *mut u16 as *mut c_void, size_of_val(&new_chunk_index));
    }
    bin.header.set_compression_state(CompressionState::Deflate);
}

pub(crate) fn deflate_bin(superbin: &mut Superbin, metabin: &mut Metabin) {
    let size_of_bin = superbin.get_data_size();

    for i in (0..255).rev() {
        let current_bin: &mut Bin = &mut metabin.bins[i];
        match current_bin.header.compression_state() {
            CompressionState::None => {
                let teardown_successful: bool = current_bin.teardown_if_unused(size_of_bin as usize);
                if !teardown_successful {
                    perform_bin_deflation(current_bin, size_of_bin as usize);
                }
            },
            _ => current_bin.header.set_chance2nd_alloc(1),
        }
    }
}

pub(crate) fn perform_arena_deflation(arena: &mut ArenaInner) -> bool {
    let superbin: &mut Superbin = &mut arena.superbins[0];

    if superbin.header.metabins_initialized() > 0 {
        let metabin_id = get_metabin_iterator(superbin);
        let metabin: Option<&mut Metabin> = superbin.metabins.get_mut(metabin_id as usize);
        if metabin.is_some() {}
    }
    todo!()
}

pub(crate) fn handle_strategy_compress(arena: &mut ArenaInner, compression_strategy: CompressionStrategy) -> bool {
    todo!()
}

pub(crate) fn decompress_bin(bin: &mut Bin) {
    if bin.chunks.is_notnull() {
        unsafe {
            let head = bin.chunks.get() as *mut CompressedContainerHead;
            let original_compression_state = (*head).original_compression_state;
            let compressed = (head as *mut u8).add(size_of::<CompressedContainerHead>());
            let target = allocate_mmap((*head).original_size as usize);
            
            if bin.header.compression_state() == CompressionState::Zstd {
                assert_eq!((*head).original_size as usize, ZSTD_decompress(target, (*head).original_size as usize, compressed as *const c_void, (*head).compressed_size as usize - size_of::<CompressedContainerHead>()));
            }
            else {
                assert_eq!(bin.header.compression_state(), CompressionState::Lz4);
                assert_eq!((*head).original_size as c_int, LZ4_decompress_safe(compressed as *const c_char, target as *mut c_char, ((*head).compressed_size as usize - size_of::<CompressedContainerHead>()) as c_int, (*head).original_size as c_int));
            }
            DECOMPRESSED_BYTES.fetch_add(((*head).original_size - (*head).compressed_size) as i64, Relaxed);
            ORIGINAL_DECOMPRESSED_SIZE.fetch_add((*head).original_size as i64, Relaxed);
            bin.header.set_compression_state(original_compression_state);
            assert!(auto_free_memory(bin.chunks.get(), (*head).compressed_size as usize, bin.header.allocated_by()));
            bin.chunks.store(target);
            bin.header.set_allocated_by(Mmap);
            bin.header.set_chance2nd_read(0);
        }
    }
}

pub(crate) fn decompress_extended(extended_pointer: *mut ExtendedHyperionPointer) {
    unsafe {
        let head = (*extended_pointer).data.get() as *mut CompressedContainerHead;
        let compressed = (head as *mut u8).add(size_of::<CompressedContainerHead>());
        let target = allocate_heap((*head).original_size as usize);
        assert!(!target.is_null());
        assert_ne!((*extended_pointer).header.compression_state(), CompressionState::None);
        assert_ne!((*extended_pointer).header.compression_state(), CompressionState::Deflate);
        
        if (*extended_pointer).header.compression_state() == CompressionState::Zstd {
            assert_eq!((*head).original_size as usize, ZSTD_decompress(target, (*head).original_size as usize, compressed as *const c_void, (*head).compressed_size as usize - size_of::<CompressedContainerHead>()));
        }
        else {
            assert_eq!((*head).original_size as c_int, LZ4_decompress_safe(compressed as *const c_char, target as *mut c_char, ((*head).compressed_size as usize - size_of::<CompressedContainerHead>()) as c_int, (*head).original_size as c_int));
        }
        DECOMPRESSED_BYTES.fetch_add(((*head).original_size - (*head).compressed_size) as i64, Relaxed);
        ORIGINAL_DECOMPRESSED_SIZE.fetch_add((*head).original_size as i64, Relaxed);
        assert!(auto_free_memory((*extended_pointer).data.get(), (*head).compressed_size as usize, (*extended_pointer).header.alloced_by()));
        (*extended_pointer).data.store(null_mut());
        (*extended_pointer).header.set_alloced_by(Heap);
        (*extended_pointer).data.store(target);
        (*extended_pointer).chance2nd_read = 0;
        (*extended_pointer).header.set_compression_state(CompressionState::None);
    }
}

pub(crate) fn compress_arena(arena: &mut ArenaInner) -> bool {
    let compression_strategy: CompressionStrategy = get_compression_strategy();

    match compression_strategy {
        CompressionStrategy::None => false,
        CompressionStrategy::Deflate => perform_arena_deflation(arena),
        _ => handle_strategy_compress(arena, compression_strategy),
    }
}
