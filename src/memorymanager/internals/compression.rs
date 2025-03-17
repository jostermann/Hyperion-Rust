use std::cmp::PartialEq;
use std::ffi::c_void;

use libc::{memcpy, memset};

use crate::memorymanager::api::AtomicMemoryPointer;
use crate::memorymanager::components::arena::ArenaInner;
use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS, BIN_ELEMENTS_DEFLATED};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::Superbin;
use crate::memorymanager::internals::allocator::{auto_allocate_memory, auto_free_memory};
use crate::memorymanager::internals::system_information::get_memory_stats;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;

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
    NONE,
    DEFLATE,
    LZ4_0,
    LZ4_1,
    ZSTD,
}

#[derive(Debug, PartialOrd, PartialEq)]
pub(crate) enum CompressionState {
    NONE = 0,
    DEFLATE = 1,
    LZ4 = 2,
    ZSTD = 3,
}

impl CompressionState {
    pub(crate) const fn into_bits(self) -> u8 {
        self as _
    }

    pub(crate) const fn from_bits(value: u8) -> Self {
        match value {
            0 => Self::NONE,
            1 => Self::DEFLATE,
            2 => Self::LZ4,
            3 => Self::ZSTD,
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

pub(crate) fn get_compression_strategy() -> CompressionStrategy {
    let sys_rate: f64 = get_memory_stats(false).sys_rate;

    if sys_rate > COMPRESSION_LIMIT_S3 {
        CompressionStrategy::ZSTD
    } else if sys_rate > COMPRESSION_LIMIT_S2 {
        CompressionStrategy::LZ4_1
    } else if sys_rate > COMPRESSION_LIMIT_S1 {
        CompressionStrategy::LZ4_0
    } else if sys_rate > COMPRESSION_LIMIT_S0 {
        CompressionStrategy::DEFLATE
    } else {
        CompressionStrategy::NONE
    }
}

pub(crate) fn get_metabin_iterator(superbin: &mut Superbin) -> u16 {
    let mut iterator_id: u16 = superbin.header.metabins_compression_iterator_id();
    superbin.header.set_metabins_compression_iterator_id(iterator_id + 1);

    if iterator_id >= superbin.header.metabins_initialized() {
        superbin.header.set_metabins_compression_iterator_id(0);
        iterator_id = 0;
    }
    iterator_id
}

pub(crate) fn pdb_copy_chunk(bin: &mut Bin, size: usize, index: usize, target: &mut AtomicMemoryPointer, nci_iterator: &mut usize, nci: &mut [u16]) {
    unsafe {
        nci[*nci_iterator] = index as u16;
        memcpy(target.get().add(size * (*nci_iterator)), bin.chunks.get().add(size * index), size);
        *nci_iterator += 1;
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
    bin.header.set_compression_state(CompressionState::DEFLATE);
}

pub(crate) fn deflate_bin(superbin: &mut Superbin, metabin: &mut Metabin) {
    let size_of_bin = superbin.get_data_size();

    for i in (0..255).rev() {
        let current_bin: &mut Bin = &mut metabin.bins[i];
        match current_bin.header.compression_state() {
            CompressionState::NONE => {
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

pub(crate) fn perform_arena_compression(arena: &mut ArenaInner, compression_strategy: CompressionStrategy) -> bool {
    todo!()
}

pub(crate) fn decompress_bin(bin: &mut Bin) {
    todo!()
}

pub(crate) fn decompress_extended(extended_pointer: *mut ExtendedHyperionPointer) {
    todo!()
}

pub(crate) fn compress_arena(arena: &mut ArenaInner) -> bool {
    let compression_strategy: CompressionStrategy = get_compression_strategy();

    match compression_strategy {
        CompressionStrategy::NONE => false,
        CompressionStrategy::DEFLATE => perform_arena_deflation(arena),
        _ => perform_arena_compression(arena, compression_strategy),
    }
}
