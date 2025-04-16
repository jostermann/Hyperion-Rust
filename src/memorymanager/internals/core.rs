use crate::memorymanager::api::NUM_ARENAS;
use crate::memorymanager::components::arena::{get_arena_mut, ArenaInner};
use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS, BIN_ELEMENTS_DEFLATED};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::{get_superbin_id, Superbin};
use crate::memorymanager::internals::allocator::{allocate_heap, auto_free_memory, auto_reallocate_memory, AllocatedBy};
use crate::memorymanager::internals::compression::{compress_arena, decompress_extended, CompressionState};
use crate::memorymanager::internals::simd_common::apply_index_search;
use crate::memorymanager::internals::system_information::get_memory_stats;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use chrono::Local;
use parking_lot::RwLock;
use std::env;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::ptr::{copy, copy_nonoverlapping, null_mut, write_bytes};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Base increment size on extended hyperion pointers larger than 8 KiB.
pub const INCREMENT_SIZE_EXT: usize = 4096;
/// Increment size on extended hyperion pointers smaller than 8 KiB.
pub const INCREMENT_SIZE_EXT_TIGHT: usize = 256;
/// Maximum amount of chained chunk indices.
pub const CONTAINER_SPLIT_BITS: usize = 3;
/// Maximum amount of chained chunks in a split container.
pub const CONTAINER_MAX_SPLITS: usize = 8;
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
    ReallocateToNormal,
}

/// Returns a raw pointer to the chunk specified by the [`HyperionPointer`].
///
/// # Safety
/// This function is intended for use on all superbins > 0.
#[allow(unreachable_code, dead_code)]
pub fn get_chunk_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) -> *mut c_void {
    #[cfg(feature = "compression")]
    {
        let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);

        return match bin.header.compression_state() {
            CompressionState::None => get_offset(arena, hyperion_pointer),
            CompressionState::Deflate => get_chunk_pointer_deflated(arena, hyperion_pointer),
            CompressionState::Lz4 | CompressionState::Zstd => {
                decompress_bin(bin);

                if bin.header.compression_state() == CompressionState::None {
                    return get_offset(arena, hyperion_pointer);
                }
                return get_chunk_pointer_deflated(arena, hyperion_pointer);
            },
        };
    }
    // log_to_file(&format!("Get chunk pointer from: {:?}", hyperion_pointer));
    let current_superbin: &mut Superbin = arena.get_superbin_ref(hyperion_pointer);
    /*log_to_file(&format!("Metadata: size of bin {} * chunk id {} = {}", current_superbin.header.size_of_bin(), hyperion_pointer.chunk_id(),
                         hyperion_pointer.chunk_id() as usize * current_superbin.header.size_of_bin() as usize
    ));*/
    let offset: usize = hyperion_pointer.chunk_id() as usize * current_superbin.header.size_of_bin() as usize;
    let chunk_addr = arena.get_bin_ref(hyperion_pointer).chunks.add_get(offset);
    chunk_addr
}

/// Returns a raw pointer to the chunk specified by the [`HyperionPointer`].
///
/// # Parameters
/// - `needed_character` is used to retrieve the corresponding extended chunk from superbin 0
#[allow(unreachable_code, dead_code, unused_variables)]
pub fn get_chunk(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, might_increment: i32, needed_character: u8) -> *mut c_void {
    // log_to_file(&format!("S6B1: is empty? {}", arena.superbins[6].get_metabin_candidate().unwrap().bins[1].chunks.is_null() as usize));
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
    // log_to_file(&format!("Get new pointer for: {:?}", hyperion_pointer));
    // log_to_file(&format!("Pointer is null: {}", data.is_null() as usize));
    data
}

/// Returns a raw pointer to a heap-allocated memory region, pointed to by the [`HyperionPointer`].
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

/// Returns a mutable reference to the [`ExtendedHyperionPointer`] responsible for the chunk containing `needed_character`.
pub fn get_chained_pointer(extended_hyperion_pointer: &mut ExtendedHyperionPointer, needed_character: u8) -> &mut ExtendedHyperionPointer {
    let ptr: *mut ExtendedHyperionPointer = extended_hyperion_pointer as *mut ExtendedHyperionPointer;

    // needed_character / 32 yields the chunk id responsible for storing needed_character
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

        if (*iterator).header.compression_state() > CompressionState::Deflate {
            decompress_extended(iterator);
        }
        iterator.as_mut().unwrap()
    }
}

/// Allocates a new memory region and returns a [`HyperionPointer`] pointing to it.
///
/// During allocation, this function automatically checks if the allocation must be done via mmap or on the heap. Depending on the size, the resulting
/// hyperion pointer either points to some mmap-ed chunk or to some chained memory on the heap.
pub fn get_new_pointer(arena: &mut ArenaInner, size: usize, chained_counter: i32) -> HyperionPointer {
    // log_to_file(&format!("S6B1: is empty? {}", arena.superbins[6].get_metabin_candidate().unwrap().bins[1].chunks.is_null() as usize));
    let superbin_id: u8 = get_superbin_id(size as u32);
    let mut new_hyperion_pointer: HyperionPointer = HyperionPointer::default();
    new_hyperion_pointer.set_superbin_id(superbin_id);

    let superbin: *mut Superbin = arena.get_superbin_ref(&mut new_hyperion_pointer) as *mut Superbin;
    allocate_bin(arena, &mut new_hyperion_pointer, superbin, chained_counter);

    let metabin: &mut Metabin = arena.get_metabin_ref(&mut new_hyperion_pointer);
    // log_to_file(&format!("New pointer reallocation: {:?}", new_hyperion_pointer));

    if new_hyperion_pointer.is_extended_pointer() {
        let extended_pointer: &mut ExtendedHyperionPointer =
            metabin.get_bin_ref(&mut new_hyperion_pointer).get_extended_pointer_to_bin_ref(&mut new_hyperion_pointer);
        let new_size = roundup(size);
        extended_pointer.header.set_alloced_by(AllocatedBy::Heap);
        extended_pointer.data.store(unsafe { allocate_heap(new_size) });
        extended_pointer.set_flags(size as i32, (new_size - size) as i16, 0, 0, CompressionState::None, chained_counter as u8);
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
    let chunk_size: u16 = superbin.get_data_size();

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

/// Allocates `chain_count` chunks in the specified metabin.
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

/// Round the specified allocation size to the next extended increment size.
///
/// [`ExtendedHyperionPointer`] increment in following steps:
/// - up to 8 KiB: 256 Bytes
/// - up to 16 KiB: 1 KiB
/// - from 16 KiB: 4 KiB
pub fn roundup(size: usize) -> usize {
    if size < 8192 {
        return (size / INCREMENT_SIZE_EXT_TIGHT + 1) * INCREMENT_SIZE_EXT_TIGHT;
    }

    if size < 16384 {
        return (size / (INCREMENT_SIZE_EXT_TIGHT * 2) + 1) * (INCREMENT_SIZE_EXT_TIGHT * 2);
    }

    (size / DYN_INCREMENT_SIZE.load(Ordering::Relaxed) + 1) * DYN_INCREMENT_SIZE.load(Ordering::Relaxed)
}

/// Reallocates the memory region pointed to by `hyperion_pointer` with the given size.
pub fn reallocate_from_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8) -> HyperionPointer {
    // log_to_file(&format!("Reallocate from container pointer: {:?}", hyperion_pointer));
    // log_to_file(&format!("S6B1: is empty? {}", arena.superbins[6].get_metabin_candidate().unwrap().bins[1].chunks.is_null() as usize));
    if hyperion_pointer.is_extended_pointer() {
        reallocate_extended_pointer(arena, hyperion_pointer, size, needed_character)
    } else {
        reallocate_hyperion_pointer(arena, hyperion_pointer, size)
    }
}

/// Reallocates the non-extended hyperion pointer.
fn reallocate_hyperion_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize) -> HyperionPointer {
    if get_superbin_id(size as u32) == hyperion_pointer.superbin_id() {
        return *hyperion_pointer;
    }

    let mut new_pointer: HyperionPointer = get_new_pointer(arena, size, 0);
    let old_data: *mut c_void = get_chunk(arena, hyperion_pointer, 1, 0);
    let new_data: *mut c_void = get_chunk(arena, &mut new_pointer, 1, 0);
    let allocation_size: u16 = arena.get_superbin_ref(hyperion_pointer).get_data_size();

    unsafe {
        // log_to_file("R1");
        // log_to_file(&format!("old_data: {}, new_data: {}, allocation_size: {}, copy size: {}", old_data.is_null() as usize, old_data.is_null() as usize, allocation_size, allocation_size.min(size as u16) as usize));
        // Copy all old data into the newly allocated chunk
        copy_nonoverlapping(old_data as *const u8, new_data as *mut u8, allocation_size.min(size as u16) as usize);
    }
    free_from_pointer(arena, hyperion_pointer);
    new_pointer
}

/// Reallocates the given extended hyperion pointer with the given size.
fn reallocate_extended_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8) -> HyperionPointer {
    let chained_pointer_cnt: u8 =
        arena.get_bin_ref(hyperion_pointer).get_extended_pointer_to_bin_ref(hyperion_pointer).header.chained_pointer_count();

    let reallocation_strategy: ReallocationStrategy = if chained_pointer_cnt > 0 || get_superbin_id(size as u32) == 0 {
        // Stay extended, since the reallocation might result in container size shrinkage. This could affect all chained memory.
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
        ReallocationStrategy::ReallocateToNormal => reallocate_shrink(arena, hyperion_pointer, size),
    }
}

/// Reallocate the given extended hyperion pointer to the given size. This might result in the container's size shrinking.
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

/// Reallocate the given extended hyperion pointer to the given size. This function ensures, that the container does not shrink.
fn reallocate_extended(
    arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer, size: usize, needed_character: u8, chained_pointer_cnt: u8,
) -> HyperionPointer {
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
    let mut extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);

    if chained_pointer_cnt > 0 {
        extended_pointer = get_chained_pointer(extended_pointer, needed_character);
    }

    if size > extended_pointer.requested_size as usize {
        // The new size is larger than the current requested size of the extended hyperion pointer.

        let total_size: usize = extended_pointer.requested_size as usize + extended_pointer.overallocated as usize;

        if size <= total_size {
            // The amount of overallocation is sufficient to cover the new size requirement. Therefore, no reallocation is needed.
            extended_pointer.overallocated -= (size - extended_pointer.requested_size as usize) as i16;
        } else {
            // The amount of overallocation is not sufficient to cover the size requirement. Therefore, a new memory region must be allocated.

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
            // To remain efficient, extended hyperion pointers have a limit of overallocation. In this case, the amount of shrinkage does not violate
            // the limit.
            extended_pointer.overallocated += shrink_by as i16;
        } else {
            // To remain efficient, extended hyperion pointers have a limit of overallocation. In this case, the amount of shrinkage violates this limit.
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

/// Frees the memory region pointed to by the [`HyperionPointer`].
pub fn free_from_pointer(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    if arena.get_bin_ref(hyperion_pointer).header.compression_state() != CompressionState::Deflate {
        free_chunks_normal(arena, hyperion_pointer);
    } else {
        free_chunks_deflated(arena, hyperion_pointer);
    }
    update_superbin(arena, hyperion_pointer)
}

/// Auto-updates the superbin.
fn update_superbin(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    let metabin_free_chunks: u8 = arena.get_metabin_ref(hyperion_pointer).free_chunks;
    let metabin: *mut Metabin = arena.get_metabin_ref(hyperion_pointer) as *mut Metabin;
    let superbin: *mut Superbin = arena.get_superbin_ref(hyperion_pointer) as *mut Superbin;
    let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);

    unsafe {
        if metabin_free_chunks == 0 {
            // Updates the metabin ring
            (*superbin).inject_metabin_into_metaring(metabin.as_mut().unwrap());
        }

        if (*metabin).id == 0 && hyperion_pointer.bin_id() == 0 {
            return;
        }

        if (*superbin).teardown_bin(bin) {
            // tears down all unused bins
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

/// Frees the chunk pointed to by the [`HyperionPointer`] without compression.
fn free_chunks_normal(arena: &mut ArenaInner, hyperion_pointer: &mut HyperionPointer) {
    if hyperion_pointer.is_extended_pointer() {
        // Get the extended pointer and free its heap memory.
        let bin: &mut Bin = arena.get_bin_ref(hyperion_pointer);
        let extended_pointer: &mut ExtendedHyperionPointer = bin.get_extended_pointer_to_bin_ref(hyperion_pointer);
        let extended_allocation_size: usize = extended_pointer.alloc_size();
        unsafe { auto_free_memory(extended_pointer.data.get(), extended_allocation_size, extended_pointer.header.alloced_by()) };
        extended_pointer.clear_data();
    } else {
        // Set the memory region to 0.
        // This branch does not free the mmap region, since this region might be reallocated during execution. All mmap regions will be freed
        // upon teardown of the memory manager.
        let chunk_pointer: *mut c_void = get_chunk_pointer(arena, hyperion_pointer);
        unsafe {
            write_bytes(chunk_pointer as *mut u8, 0, arena.get_superbin_ref(hyperion_pointer).header.size_of_bin() as usize);
        }
    }

    // Set the metabin and bin as unused.
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
        let factor: f64 = (1.0 - get_memory_stats(false).read().sys_rate).powf(2.0);
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

pub fn memory_manager_statistics() {
    let now = Local::now();
    let time_str = now.format("-%y%m%dT%H%M%S-").to_string();
    let filename = format!("Memory Manager statistics {time_str}.csv");

    let path = match env::current_dir() {
        Ok(cwd) => cwd.join(filename),
        Err(e) => {
            eprintln!("Could not get current working directory: {}", e);
            return;
        }
    };

    let mut writer = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => BufWriter::new(file),
        Err(e) => {
            eprintln!("Could not create a file for the memory manager statistics {}", e);
            return;
        }
    };

    if let Err(e) = writeln!(
        writer,
        "Arena,Superbin,Metabin,Bins allocated,Used chunks,Unused chunks,Extended chunks [KiB],Extended chunks overallocation [KiB],Overallocation [KiB],Total allocation size"
    ) {
        eprintln!("Failed to write CSV header: {}", e);
        return;
    }

    for arena_id in 0..NUM_ARENAS {
        let arena = unsafe { (*get_arena_mut(arena_id as u32)).spinlock.lock() };

        for (superbin_id, superbin) in arena.superbins.iter().enumerate() {
            for metabin_id in 0..superbin.header.metabins_initialized() {
                if let Some(metabin) = superbin.metabins.get(metabin_id as usize) {
                    let mut ext_chunks_used: u64 = 0;
                    let mut ext_chunk_overalloc: u64 = 0;
                    let mut chunks_used: u64 = 0;
                    let mut bins_allocated: u64 = 0;

                    for bin in &metabin.bins {
                        if bin.chunks.is_notnull() {
                            bins_allocated += 1;

                            for bin_mask in &bin.chunk_usage_mask {
                                chunks_used += (32 - bin_mask.count_ones()) as u64;
                            }

                            if superbin_id == 0 {
                                let mut extended_pointer = bin.chunks.read() as *const ExtendedHyperionPointer;

                                for _ in 0..BIN_ELEMENTS {
                                    unsafe {
                                        ext_chunks_used += (*extended_pointer).requested_size as u64;
                                        ext_chunk_overalloc += (*extended_pointer).overallocated as u64;
                                        extended_pointer = extended_pointer.add(1);
                                    }
                                }
                            }
                        }
                    }

                    let unused_chunks = (bins_allocated * BIN_ELEMENTS as u64) - chunks_used;
                    let overallocation = unused_chunks * superbin.header.size_of_bin() as u64 / 1024;

                    if let Err(e) = writeln!(
                        writer,
                        "{},{},{},{},{},{},{},{},{},{}",
                        arena_id,
                        superbin_id,
                        metabin_id,
                        bins_allocated,
                        chunks_used,
                        unused_chunks,
                        ext_chunks_used / 1024,
                        ext_chunk_overalloc / 1024,
                        overallocation,
                        (chunks_used + unused_chunks) * superbin.header.size_of_bin() as u64
                    ) {
                        eprintln!("Error writing row: {}", e);
                        return;
                    }
                }
            }
        }
    }
    if let Err(e) = writer.flush() {
        eprintln!("Failed to flush memory manager statistics file: {}", e);
    }
}
