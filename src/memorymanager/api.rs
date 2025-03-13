use std::ffi::c_void;

use crate::memorymanager::components::arena::{get_arena_mut, ArenaInner, NUM_ARENAS};
pub use crate::memorymanager::components::arena::{get_next_arena, Arena};
use crate::memorymanager::components::bin::Bin;
use crate::memorymanager::components::superbin::SUPERBLOCK_ARRAY_MAXSIZE;
use crate::memorymanager::internals::allocator::{allocate_heap, auto_free_memory, free_mmap, AllocatedBy};
use crate::memorymanager::internals::compression::{decompress_extended, CompressionState};
use crate::memorymanager::internals::core::{free_from_pointer, get_chunk, get_new_pointer, reallocate_from_pointer, roundup};
pub use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
pub use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
pub use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
pub use crate::memorymanager::internals::core::{CONTAINER_SPLIT_BITS, CONTAINER_MAX_SPLITS};

pub const ARENA_COMPRESSION: usize = 16646144;

pub struct SegmentChain {
    pub chars: [u8; 1usize << CONTAINER_SPLIT_BITS],
    pub pointer: [AtomicMemoryPointer; 1usize << CONTAINER_SPLIT_BITS]
}

pub fn initialize() {
    for i in 0..NUM_ARENAS {
        let arena: &mut Arena = unsafe { get_arena_mut(i as u32).as_mut().unwrap() };
        let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut arena.lock();
        inner.compression_cache = AtomicMemoryPointer::new();
        inner.compression_iterator = 1;
        for j in 0..SUPERBLOCK_ARRAY_MAXSIZE {
            inner.initialize_superbin(j as u16);
        }
    }
}

pub fn teardown() {
    for i in 0..NUM_ARENAS {
        let arena: &mut Arena = unsafe { get_arena_mut(i as u32).as_mut().unwrap() };
        let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut arena.lock();
        inner.teardown_all_superbins();

        if inner.compression_cache.is_notnull() {
            unsafe {
                free_mmap(inner.compression_cache.get(), ARENA_COMPRESSION);
            }
        }
    }
}

pub fn register_chained_memory(
    arena: *mut Arena, hyperion_pointer: *mut HyperionPointer, character: u8, segment: *mut c_void, size: usize, inplace: bool, overallocated: i32
) {
    let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut unsafe { arena.as_mut().unwrap() }.lock();
    let bin: &mut Bin = inner.get_bin_ref(unsafe { hyperion_pointer.as_mut().unwrap() });
    let base: *mut ExtendedHyperionPointer = bin.chunks.get_as_extended();

    unsafe {
        let chain_head: *mut ExtendedHyperionPointer = base.add((*hyperion_pointer).chunk_id() as usize);
        let mut chain_pointer: *mut ExtendedHyperionPointer = chain_head.add((character >> 5) as usize);

        if !inplace {
            while (*chain_pointer).data.is_null() {
                chain_pointer = chain_pointer.sub(1);
            }
        }

        if (*chain_pointer).data.is_notnull() {
            auto_free_memory(
                (*chain_pointer).data.get(),
                (*chain_pointer).requested_size as usize + (*chain_pointer).overallocated as usize,
                (*chain_pointer).header.alloced_by()
            );
        }
        (*chain_pointer).data = AtomicMemoryPointer::new();
        (*chain_pointer).data.store(segment);
        (*chain_pointer).requested_size = size as i32;
        (*chain_pointer).overallocated = overallocated as i16;
        (*chain_pointer).header.set_alloced_by(AllocatedBy::Heap);
    }
}

pub fn is_chained_pointer(arena: *mut Arena, hyperion_pointer: *mut HyperionPointer) -> bool {
    let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut unsafe { arena.as_mut().unwrap() }.lock();
    let bin: &mut Bin = inner.get_bin_ref(unsafe { hyperion_pointer.as_mut().unwrap() });
    let base: *mut ExtendedHyperionPointer = bin.chunks.get_as_extended();
    unsafe {
        let chain_head: *mut ExtendedHyperionPointer = base.add((*hyperion_pointer).chunk_id() as usize);
        (*chain_head).header.chained_pointer_count() != 0
    }
}

pub fn get_all_chained_pointer(segment_chain: &mut SegmentChain, arena: &mut Arena, hyperion_pointer: &mut HyperionPointer) -> i32 {
    let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut arena.lock();
    let bin: &mut Bin = inner.get_bin_ref(hyperion_pointer);
    let base: *mut ExtendedHyperionPointer = bin.chunks.get_as_extended();
    let mut elements: usize = 0;

    unsafe {
        let chain_head: *mut ExtendedHyperionPointer = base.add(hyperion_pointer.chunk_id() as usize);

        if (*chain_head).header.chained_pointer_count() > 0 {
            let increment: usize = 256 / (1usize << CONTAINER_SPLIT_BITS);
            for i in (0..256).step_by(increment) {
                if (*chain_head).data.is_notnull() {
                    if (*chain_head).header.compression_state() > CompressionState::DEFLATE {
                        decompress_extended(chain_head);
                    }
                    segment_chain.chars[elements] = i as u8;
                    segment_chain.pointer[elements] = AtomicMemoryPointer::new();
                    segment_chain.pointer[elements].store((*chain_head).data.get());
                    (*chain_head).chance2nd_read = 0;
                    elements += 1;
                }
            }
        } else {
            segment_chain.chars[elements] = 0;
            segment_chain.pointer[elements] = AtomicMemoryPointer::new();
            segment_chain.pointer[elements].store((*chain_head).data.get());
            elements += 1;
        }
    }
    elements as i32
}

pub fn get_chained_pointer(arena: &mut Arena, hyperion_pointer: &mut HyperionPointer, character: u8, init: bool, size: usize) -> *mut c_void {
    let inner: &mut spin::mutex::MutexGuard<ArenaInner> = &mut arena.lock();
    let bin: &mut Bin = inner.get_bin_ref(hyperion_pointer);
    let base: *mut ExtendedHyperionPointer = bin.chunks.get_as_extended();
    let mut offset: i32 = (character >> (8 - CONTAINER_SPLIT_BITS)) as i32;

    unsafe {
        let chain_head: *mut ExtendedHyperionPointer = base.add(hyperion_pointer.chunk_id() as usize);
        let mut char_entry: *mut ExtendedHyperionPointer = chain_head.add(offset as usize);

        if (*char_entry).data.is_null() {
            if init {
                let target_size = roundup(size);
                (*char_entry).header.set_alloced_by(AllocatedBy::Heap);
                (*char_entry).data.store(allocate_heap(target_size));
                //(*char_entry).header.set_alloced_by(auto_allocate_memory(&mut (*char_entry).data, target_size));
                (*char_entry).set_flags(size as i32, (target_size - size) as i16, 0, 0, CompressionState::NONE, offset as u8);
            } else {
                while offset >= 0 {
                    if (*char_entry).data.is_notnull() {
                        break;
                    }
                    char_entry = char_entry.sub(1);
                    offset -= 1;
                }
            }
        }
        (*char_entry).chance2nd_read = 0;

        if (*char_entry).header.compression_state() > CompressionState::DEFLATE {
            decompress_extended(char_entry);
        }
        (*char_entry).data.get()
    }
}

pub fn get_pointer(arena: *mut Arena, hyperion_pointer: *mut HyperionPointer, might_increment: i32, needed_character: u8) -> *mut c_void {
    get_chunk(&mut unsafe { arena.as_mut().unwrap() }.lock(), unsafe { hyperion_pointer.as_mut().unwrap() }, might_increment, needed_character)
}

pub fn reallocate(arena: *mut Arena, hyperion_pointer: *mut HyperionPointer, size: usize, needed_character: u8) -> HyperionPointer {
    reallocate_from_pointer(&mut unsafe { arena.as_mut().unwrap() }.lock(), unsafe { hyperion_pointer.as_mut().unwrap() }, size, needed_character)
}

pub fn malloc_chained(arena: &mut Arena, size: usize, chain_count: i32) -> HyperionPointer {
    get_new_pointer(&mut arena.lock(), size, chain_count)
}

pub fn malloc(arena: *mut Arena, size: usize) -> HyperionPointer {
    get_new_pointer(&mut unsafe { arena.as_mut().unwrap() }.lock(), size, 0)
}

pub fn free(arena: *mut Arena, hyperion_pointer: *mut HyperionPointer) {
    free_from_pointer(&mut unsafe { arena.as_mut().unwrap() }.lock(), unsafe { hyperion_pointer.as_mut().unwrap() });
}

#[cfg(test)]
mod test_global {
    use std::thread;

    use crate::memorymanager::api::*;

    #[test]
    fn test() {
        /*initialize();
        const IT: usize = 20000000;

        let handle1 = thread::Builder::new()
            .name("Test_Thread1".into())
            .spawn(|| {
                const ITERATIONS: usize = IT / 2;
                let arena = unsafe { get_next_arena().as_mut().unwrap() };
                let mut vec: Vec<HyperionPointer> = Vec::with_capacity(ITERATIONS);

                for i in 0..ITERATIONS {
                    let size = 200;
                    vec.push(malloc(arena, size));
                    let _ = is_chained_pointer(arena, &mut vec[i]);
                    let _ = get_pointer(arena, &mut vec[i], 1, 0);
                }

                for i in 0..ITERATIONS {
                    let current_pointer = &mut vec[i];
                    vec[i] = reallocate(arena, current_pointer, 500, 0);
                }
            })
            .unwrap();

        let handle2 = thread::Builder::new()
            .name("Test_Thread2".into())
            .spawn(|| {
                const ITERATIONS: usize = IT / 2;
                let arena = unsafe { get_next_arena().as_mut().unwrap() };
                let mut vec: Vec<HyperionPointer> = Vec::with_capacity(ITERATIONS);

                for i in 0..ITERATIONS {
                    let size = 200;
                    vec.push(malloc(arena, size));
                    let _ = is_chained_pointer(arena, &mut vec[i]);
                    let _ = get_pointer(arena, &mut vec[i], 1, 0);
                }

                for i in 0..ITERATIONS {
                    let current_pointer = &mut vec[i];
                    vec[i] = reallocate(arena, current_pointer, 500, 0);
                }
            })
        .unwrap();
        handle1.join().unwrap();
        handle2.join().unwrap();

        teardown();*/
    }
}
