use std::array::from_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

use spin::mutex::Mutex;
use spin::MutexGuard;

use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::{Superbin, SUPERBLOCK_ARRAY_MAXSIZE};
use crate::memorymanager::internals::allocator::free_mmap;
use crate::memorymanager::internals::compression::{CompressionSlidingWindow, SLIDING_WINDOW_SIZE};
use crate::memorymanager::internals::simd_common::prefetch;
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;

pub(crate) const NUM_ARENAS: usize = 2;
pub(crate) const COMPRESSION: usize = 16646144;

pub static mut ARENAS: Vec<Arena> = vec![];
static INIT_ONCE: Once = Once::new();
static INIT_ITERATOR: AtomicUsize = AtomicUsize::new(0);

pub fn init_arenas() {
    unsafe {
        INIT_ONCE.call_once(|| {
            ARENAS.reserve(NUM_ARENAS);
            for _ in 0..NUM_ARENAS {
                ARENAS.push(Arena::default())
            }
        });
    }
}

pub fn get_next_arena() -> *mut Arena {
    init_arenas();
    unsafe {
        let arena: *mut Arena = &mut ARENAS[INIT_ITERATOR.fetch_sub(1, Ordering::SeqCst) % NUM_ARENAS] as *mut Arena;
        arena
    }
}

pub fn get_arena_mut(key: u32) -> *mut Arena {
    init_arenas();
    unsafe { &mut ARENAS[key as usize % NUM_ARENAS] as *mut Arena }
}

pub struct ArenaInner {
    pub compression_cache: AtomicMemoryPointer,
    pub compression_iterator: i16,
    pub sliding_window: [CompressionSlidingWindow; SLIDING_WINDOW_SIZE],
    pub superbins: [Superbin; SUPERBLOCK_ARRAY_MAXSIZE]
}

impl ArenaInner {
    pub(crate) fn initialize_superbin(&mut self, index: u16) {
        self.superbins[index as usize].initialize(index);
    }

    pub(crate) fn get_superbin_ref(&mut self, hyperion_pointer: &mut HyperionPointer) -> &mut Superbin {
        &mut self.superbins[hyperion_pointer.superbin_id() as usize]
    }

    pub(crate) fn get_metabin_ref(&mut self, hyperion_pointer: &mut HyperionPointer) -> &mut Metabin {
        let superbin = self.get_superbin_ref(hyperion_pointer);
        superbin.metabins.get_mut(hyperion_pointer.metabin_id() as usize).unwrap()
    }

    pub(crate) fn get_bin_ref(&mut self, hyperion_pointer: &mut HyperionPointer) -> &mut Bin {
        let metabin = self.get_metabin_ref(hyperion_pointer);
        metabin.get_bin_ref(hyperion_pointer)
    }

    pub(crate) fn teardown_all_superbins(&mut self) {
        for i in 0..SUPERBLOCK_ARRAY_MAXSIZE {
            self.teardown_superblock(i as u16);
        }
    }

    pub(crate) fn teardown_superblock(&mut self, index: u16) {
        let superbin: &mut Superbin = &mut self.superbins[index as usize];

        for i in 0..superbin.header.metabins_initialized() {
            if let Some(metabin) = superbin.metabins.get_mut(i as usize) {
                metabin.teardown(superbin.header.size_of_bin() as usize);
            }
        }

        if !superbin.bin_cache.is_null() {
            unsafe { free_mmap(superbin.bin_cache.get(), superbin.header.size_of_bin() as usize * BIN_ELEMENTS) };
        }
    }
}

pub struct Arena {
    pub spinlock: spin::Mutex<ArenaInner>
}

impl Default for Arena {
    fn default() -> Self {
        let mut superbins: [Superbin; SUPERBLOCK_ARRAY_MAXSIZE] = from_fn(|_| Superbin::new());
        for (i, superbin) in superbins.iter_mut().enumerate() {
            superbin.initialize(i as u16);
        }

        Arena {
            spinlock: Mutex::new(ArenaInner {
                compression_cache: AtomicMemoryPointer::new(),
                compression_iterator: 1,
                sliding_window: [CompressionSlidingWindow::default(); SLIDING_WINDOW_SIZE],
                superbins
            })
        }
    }
}

impl Arena {
    pub fn lock(&mut self) -> MutexGuard<ArenaInner> {
        self.spinlock.lock()
    }
}

#[cfg(test)]
mod arena_test {
    #[test]
    fn test_arena() {
        assert_eq!(1, 1);
    }
}
