use crate::memorymanager::components::arena::{ArenaInner, NUM_ARENAS};
use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS, BIN_ELEMENTS_DEFLATED};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::{get_sblock_id, Superbin};
use crate::memorymanager::internals::allocator::{allocate_heap, auto_free_memory, auto_reallocate_memory, AllocatedBy};
use crate::memorymanager::internals::compression::{compress_arena, decompress_bin, decompress_extended, CompressionState};
use crate::memorymanager::internals::simd_common::apply_index_search;
use crate::memorymanager::internals::system_information::get_memory_stats;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use spin::RwLock;
use std::ffi::c_void;
use std::ptr::{copy, null_mut, write_bytes};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const INCREMENT_SIZE_EXT: usize = 4096;
pub const INCREMENT_SIZE_EXT_TIGHT: usize = 256;
pub const CONTAINER_SPLIT_BITS: usize = 3;
pub const CONTAINER_MAX_SPLITS: usize = 1 << CONTAINER_SPLIT_BITS;
#[allow(unused)]
pub const PROBE_COMPRESSION_INTERVAL_INACTIVE: usize = 16777216;
pub const OVERALLOCATION_CAPACITY: usize = 5120;
#[allow(unused)]
pub static DYN_INCREMENT_SIZE: AtomicUsize = AtomicUsize::new(INCREMENT_SIZE_EXT);
#[allow(unused)]
pub static DYN_PROBE_INTERVAL: AtomicUsize = AtomicUsize::new(PROBE_COMPRESSION_INTERVAL_INACTIVE);

pub static PROBE_COMPRESSION: RwLock<fn(&mut ArenaInner)> = RwLock::new(probe_compression_with);

enum ReallocationStrategy {
    StayExtended,
    ReallocateToNormal
}

#[allow(unreachable_code, dead_code)]
pub fn get_chunk_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) -> *mut c_void {
    #[cfg(feature = "compression")]
    {
        let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);

        return match bin.header.compression_state() {
            CompressionState::NONE => get_offset(arena, hyperion_pointer),
            CompressionState::DEFLATE => get_chunk_pointer_deflated(arena, hyperion_pointer),
            CompressionState::LZ4 | CompressionState::ZSTD => {
                decompress_bin(bin);

                if bin.header.compression_state() == CompressionState::NONE {
                    return get_offset(arena, hyperion_pointer);
                }
                return get_chunk_pointer_deflated(arena, hyperion_pointer);
            }
        };
    }

    let current_superbin: &mut Superbin = arena.get_superbin_ref(hyperion_pointer);
    let offset: usize = hyperion_pointer.chunk_id() as usize * current_superbin.header.size_of_bin() as usize;
    arena.get_bin_ref(hyperion_pointer).chunks.add_get(offset)
}

// ehemals ohm_getpointer
#[allow(unreachable_code, dead_code, unused_variables)]
pub fn get_chunk(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, might_increment: i32, needed_character: u8) -> *mut c_void {
    if hyperion_pointer.is_extended_pointer() {
        return get_chunk_pointer_from_extended(arena, hyperion_pointer, needed_character);
    }

    #[cfg(feature = "migration")]
    {
        let new_chunk: *mut c_void = create_new_chunks(arena, hyperion_pointer, might_increment);
        if !new_chunk.is_null() {
            return new_chunk;
        }
    }

    let data: *mut c_void = get_chunk_pointer(arena, hyperion_pointer);
    let current_bin_from_pointer: &mut Bin = arena.get_bin_ref(hyperion_pointer);
    current_bin_from_pointer.header.set_chance2nd_read(0);
    PROBE_COMPRESSION.read()(arena);
    data
}

pub fn get_chunk_pointer_from_extended(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, needed_character: u8) -> *mut c_void {
    let extended_pointer_data: *mut c_void = {
        let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
        let extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);
        let extended_pointer: &mut ExtendedHyperionPointer = if extended_pointer.header.chained_pointer_count() != 0 {
            get_chained_pointer(extended_pointer, needed_character)
        } else {
            extended_pointer
        };
        extended_pointer.chance2nd_read = 0;
        extended_pointer.data.get()
    };
    PROBE_COMPRESSION.read()(arena);
    extended_pointer_data
}

pub fn get_chunk_pointer_deflated(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) -> *mut c_void {
    let mut full_index: i32 = 0;
    let size_of_bin: u16 = arena.get_superbin_ref(hyperion_pointer).header.size_of_bin();
    let bin = arena.get_bin_ref(hyperion_pointer);

    for i in 0..BIN_ELEMENTS / 256 {
        let index: i32 = apply_index_search(hyperion_pointer.chunk_id(), bin.chunk_usage_mask[i * 8] as *const u32);
        if index >= 0 {
            return bin.chunks.add_get(size_of_bin as usize * (index + full_index) as usize);
        }
        full_index += 16;
    }
    null_mut()
}

pub fn get_chained_pointer(extended_hyperion_pointer: &mut ExtendedHyperionPointer, needed_character: u8) -> &mut ExtendedHyperionPointer {
    let ptr: *mut ExtendedHyperionPointer = extended_hyperion_pointer as *mut ExtendedHyperionPointer;
    let mut offset: i32 = needed_character as i32 >> (8 - CONTAINER_SPLIT_BITS);

    unsafe {
        let mut iterator = ptr.add(offset as usize);

        while offset >= 0 {
            if (*iterator).has_data() {
                break;
            }
            iterator = iterator.offset(-1);

            if offset == 0 {
                break;
            }
            offset -= 1;
        }

        if (*iterator).header.compression_state() > CompressionState::DEFLATE {
            decompress_extended(iterator);
        }
        iterator.as_mut().unwrap()
    }
}

pub fn get_new_pointer(arena: &mut ArenaInner, size: usize, chained_counter: i32) -> HyperionPointer {
    let superbin_id: u8 = get_sblock_id(size as u32);
    let mut new_hyperion_pointer: HyperionPointer = HyperionPointer::default();
    new_hyperion_pointer.set_superbin_id(superbin_id);

    let superbin: *mut Superbin = arena.get_superbin_ref(&mut new_hyperion_pointer) as *mut Superbin;
    allocate_bin(arena, &mut new_hyperion_pointer, superbin, chained_counter);

    let metabin: &mut Metabin = arena.get_metabin_ref(&mut new_hyperion_pointer);

    if new_hyperion_pointer.is_extended_pointer() {
        let extended_pointer: &mut ExtendedHyperionPointer =
            metabin.get_bin_ref(&mut new_hyperion_pointer).get_extended_pointer_to_bin_ref(&mut new_hyperion_pointer);
        let new_size = roundup(size);
        extended_pointer.header.set_alloced_by(AllocatedBy::Heap);
        extended_pointer.data.store(unsafe { allocate_heap(new_size) });
        // extended_pointer.header.set_alloced_by(unsafe { auto_allocate_memory(&mut extended_pointer.data, new_size) });
        extended_pointer.set_flags(size as i32, (new_size - size) as i16, 0, 0, CompressionState::NONE, chained_counter as u8);
    }
    new_hyperion_pointer
}

pub fn create_new_chunks(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, might_increment: i32) -> *mut c_void {
    if might_increment != 0 {
        return null_mut();
    }

    let superbin: &mut Superbin = arena.get_superbin_ref(hyperion_pointer);
    let num_metabins_initialized: u16 = superbin.header.metabins_initialized() - 1;
    let first_metabin_id: u16 = superbin.metabin_ring[0];
    let chunk_size: u16 = superbin.get_datablock_size();

    let current_metabin_id: u16 = hyperion_pointer.metabin_id();

    if current_metabin_id >= num_metabins_initialized && current_metabin_id > first_metabin_id {
        let mut new_hyperion_pointer: HyperionPointer = get_new_pointer(arena, chunk_size as usize, 0);

        let new_data: *mut c_void = get_chunk_pointer(arena, &mut new_hyperion_pointer);
        unsafe {
            copy(get_chunk_pointer(arena, hyperion_pointer) as *const u8, new_data as *mut u8, chunk_size as usize);
        }

        free_from_pointer(arena, hyperion_pointer);
        *hyperion_pointer = new_hyperion_pointer;
        return new_data;
    }
    null_mut()
}

pub fn get_offset(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) -> *mut c_void {
    let offset: usize = hyperion_pointer.chunk_id() as usize * arena.get_superbin_ref(hyperion_pointer).header.size_of_bin() as usize;
    arena.get_bin_ref(hyperion_pointer).chunks.add_get(offset)
}

pub fn allocate_bin(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, superbin: *mut Superbin, chain_count: i32) {
    let metabin: &mut Metabin = arena.get_superbin_ref(hyperion_pointer).get_metabin_candidate().unwrap();
    let superbin: &mut Superbin = unsafe { superbin.as_mut().unwrap() };
    if !metabin.allocate_bin(hyperion_pointer, superbin, chain_count) {
        metabin.free_chunks = 0;
        superbin.self_update_metaring();
        return allocate_bin(arena, hyperion_pointer, superbin, chain_count);
    }
    hyperion_pointer.set_metabin_id(metabin.id);
}

pub fn roundup(size: usize) -> usize {
    if size < 8192 {
        return (size / INCREMENT_SIZE_EXT_TIGHT + 1) * INCREMENT_SIZE_EXT_TIGHT;
    }

    if size < 16384 {
        return (size / (INCREMENT_SIZE_EXT_TIGHT * 2) + 1) * (INCREMENT_SIZE_EXT_TIGHT * 2);
    }

    (size / DYN_INCREMENT_SIZE.load(Ordering::Relaxed) + 1) * DYN_INCREMENT_SIZE.load(Ordering::Relaxed)
}

pub fn reallocate_from_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8) -> HyperionPointer {
    if hyperion_pointer.is_extended_pointer() {
        reallocate_extended_pointer(arena, hyperion_pointer, size, needed_character)
    } else {
        reallocate_hyperion_pointer(arena, hyperion_pointer, size)
    }
}

fn reallocate_hyperion_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize) -> HyperionPointer {
    if get_sblock_id(size as u32) == hyperion_pointer.superbin_id() {
        return *hyperion_pointer;
    }

    let mut new_pointer: HyperionPointer = get_new_pointer(arena, size, 0);
    let old_data: *mut c_void = get_chunk(arena, hyperion_pointer, 1, 0);
    let new_data: *mut c_void = get_chunk(arena, &mut new_pointer, 1, 0);
    let allocation_size: u16 = arena.get_superbin_ref(hyperion_pointer).get_datablock_size();
    unsafe {
        copy(old_data as *const u8, new_data as *mut u8, allocation_size.min(size as u16) as usize);
        /*memcpy(
            new_data,
            old_data,
            if allocation_size > size as u16 {
                size as size_t
            } else {
                allocation_size as size_t
            }
        );*/
    }
    free_from_pointer(arena, hyperion_pointer);
    new_pointer
}

fn reallocate_extended_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8) -> HyperionPointer {
    let chained_pointer_cnt: u8 =
        arena.get_bin_ref(hyperion_pointer).get_extended_pointer_to_bin_ref(hyperion_pointer).header.chained_pointer_count();

    let reallocation_strategy: ReallocationStrategy = if chained_pointer_cnt > 0 || get_sblock_id(size as u32) == 0 {
        ReallocationStrategy::StayExtended
    } else {
        ReallocationStrategy::ReallocateToNormal
    };

    #[cfg(feature = "compression")]
    {
        let extended_pointer: &mut ExtendedHyperionPointer = arena.get_bin_ref(hyperion_pointer).get_extended_pointer_to_bin_ref(hyperion_pointer);
        if extended_pointer.header.compression_state() as u8 > 1 {
            decompress_extended(extended_pointer);
        }
    }

    match reallocation_strategy {
        ReallocationStrategy::StayExtended => reallocate_extended(arena, hyperion_pointer, size, needed_character, chained_pointer_cnt),
        ReallocationStrategy::ReallocateToNormal => reallocate_shrink(arena, hyperion_pointer, size)
    }
}

fn reallocate_shrink(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize) -> HyperionPointer {
    let mut new_pointer: HyperionPointer = get_new_pointer(arena, size, 0);
    let new_data: *mut c_void = get_chunk(arena, &mut new_pointer, 1, 0);
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
    let extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);

    unsafe {
        copy(extended_pointer.data.get() as *const u8, new_data as *mut u8, extended_pointer.requested_size.min(size as i32) as usize);
    }
    free_from_pointer(arena, hyperion_pointer);
    new_pointer
}

fn reallocate_extended(
    arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8, chained_pointer_cnt: u8
) -> HyperionPointer {
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
    let mut extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);

    if chained_pointer_cnt > 0 {
        extended_pointer = get_chained_pointer(extended_pointer, needed_character);
    }

    if size > extended_pointer.requested_size as usize {
        let total_size: usize = extended_pointer.requested_size as usize + extended_pointer.overallocated as usize;
        if size <= total_size {
            extended_pointer.overallocated -= (size - extended_pointer.requested_size as usize) as i16;
        } else {
            let new_size: usize = roundup(size);
            let allocation_size: usize = extended_pointer.alloc_size();
            let allocation_type: AllocatedBy = extended_pointer.header.alloced_by();
            extended_pointer
                .header
                .set_alloced_by(unsafe { auto_reallocate_memory(&mut extended_pointer.data, allocation_size, new_size, allocation_type) });
            extended_pointer.overallocated = (new_size - size) as i16;
        }
    } else {
        let shrink_by: usize = extended_pointer.requested_size as usize - size;

        if extended_pointer.overallocated as usize + shrink_by < OVERALLOCATION_CAPACITY {
            extended_pointer.overallocated += shrink_by as i16;
        } else {
            let new_size: usize = roundup(size);
            let allocation_size: usize = extended_pointer.alloc_size();
            let allocation_type: AllocatedBy = extended_pointer.header.alloced_by();
            extended_pointer
                .header
                .set_alloced_by(unsafe { auto_reallocate_memory(&mut extended_pointer.data, allocation_size, new_size, allocation_type) });
            extended_pointer.overallocated = 0;
        }
    }
    extended_pointer.requested_size = size as i32;
    extended_pointer.header.set_chance2nd_realloc(0);
    *hyperion_pointer
}

pub fn free_from_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    if arena.get_bin_ref(hyperion_pointer).header.compression_state() != CompressionState::DEFLATE {
        free_chunks_normal(arena, hyperion_pointer);
    } else {
        free_chunks_deflated(arena, hyperion_pointer);
    }
    update_superbin(arena, hyperion_pointer)
}

fn update_superbin(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    let metabin_free_chunks: u8 = arena.get_metabin_ref(hyperion_pointer).free_chunks;
    let metabin: *mut Metabin = arena.get_metabin_ref(hyperion_pointer) as *mut Metabin;
    let superbin: *mut Superbin = arena.get_superbin_ref(hyperion_pointer) as *mut Superbin;
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);

    unsafe {
        if metabin_free_chunks == 0 {
            (*superbin).inject_metabin_into_metaring(metabin.as_mut().unwrap());
        }

        if (*metabin).id == 0 && hyperion_pointer.bin_id() == 0 {
            return;
        }

        if (*superbin).teardown_bin(bin) {
            (*superbin).delete_unused_metabins();
        }
    };
}

fn free_chunks_deflated(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    let bin_size: u16 = arena.get_superbin_ref(hyperion_pointer).header.size_of_bin();
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);

    unsafe {
        let mut probe: *mut u16 = bin.chunk_usage_mask[0] as *mut u16;
        for i in 0..BIN_ELEMENTS_DEFLATED {
            if (*probe) == hyperion_pointer.chunk_id() {
                let chunk: *mut c_void = bin.chunks.add_get(bin_size as usize * i);
                write_bytes(chunk as *mut u8, 0, bin_size as usize);
                *probe = u16::MAX;
                arena.get_metabin_ref(hyperion_pointer).free_chunks += 1;
                break;
            }
            probe = probe.add(1);
        }
    }
}

fn free_chunks_normal(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    if hyperion_pointer.is_extended_pointer() {
        let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
        let extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);
        let extended_allocation_size: usize = extended_pointer.alloc_size();
        unsafe { auto_free_memory(extended_pointer.data.get(), extended_allocation_size, extended_pointer.header.alloced_by()) };
        extended_pointer.clear_data();
    } else {
        let chunk_pointer: *mut c_void = get_chunk_pointer(arena, hyperion_pointer);
        unsafe {
            write_bytes(chunk_pointer as *mut u8, 0, arena.get_superbin_ref(hyperion_pointer).header.size_of_bin() as usize);
        }
    }

    let metabin: &mut Metabin = arena.get_metabin_ref(hyperion_pointer);
    metabin.set_bin_as_unused(hyperion_pointer.bin_id() as usize, hyperion_pointer.chunk_id() as usize);
    metabin.free_chunks = metabin.free_chunks.wrapping_add(1);
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
    bin.toggle_chunk_usage(hyperion_pointer.chunk_id() as usize);
}

#[allow(dead_code, unreachable_code, unused)]
pub fn probe_compression_with(arena: &mut ArenaInner) {
    if DYN_PROBE_INTERVAL.fetch_sub(1, Ordering::SeqCst) == 0 {
        compress_arena(arena);
        let factor: f64 = (1.0 - get_memory_stats(false).sys_rate).powf(2.0);
        DYN_PROBE_INTERVAL.store((PROBE_COMPRESSION_INTERVAL_INACTIVE as f64 * factor) as usize, Ordering::SeqCst)
    }
}

#[allow(unreachable_code, dead_code, unused_variables)]
pub fn probe_compression_without(arena: &mut ArenaInner) {
    #[cfg(feature = "compression")]
    {
        if NUM_ARENAS != 1 {
            return;
        }

        if DYN_PROBE_INTERVAL.fetch_sub(1, Ordering::SeqCst) == 0 {
            if compress_arena(arena) {
                let mut probe_function = PROBE_COMPRESSION.write();
                *probe_function = probe_compression_with;
                DYN_INCREMENT_SIZE.store(INCREMENT_SIZE_EXT_TIGHT, Ordering::SeqCst);
            }
            DYN_PROBE_INTERVAL.store(PROBE_COMPRESSION_INTERVAL_INACTIVE, Ordering::SeqCst);
        }
    }
}

