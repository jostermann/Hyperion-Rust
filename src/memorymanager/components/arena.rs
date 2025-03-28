use crate::memorymanager::components::bin::{Bin, BIN_ELEMENTS};
use crate::memorymanager::components::metabin::Metabin;
use crate::memorymanager::components::superbin::{Superbin, SUPERBIN_ARRAY_MAXSIZE};
use crate::memorymanager::internals::allocator::free_mmap;
use crate::memorymanager::internals::compression::{CompressionSlidingWindow, SLIDING_WINDOW_SIZE};
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use lazy_static::lazy_static;
use spin::mutex::Mutex;
use spin::{MutexGuard, RwLock};
use std::array::from_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

pub const NUM_ARENAS: usize = 1;
pub(crate) const COMPRESSION: usize = 16646144;

lazy_static! {
    pub static ref ARENAS: RwLock<Vec<Arena>> = RwLock::new(vec![]);
    static ref INIT_ITERATOR: AtomicUsize = AtomicUsize::new(0);
}

static INIT_ONCE: Once = Once::new();

pub fn init_arenas() {
    INIT_ONCE.call_once(|| {
        let mut rw_lock = ARENAS.write();
        rw_lock.reserve(NUM_ARENAS);
        for _ in 0..NUM_ARENAS {
            rw_lock.push(Arena::default())
        }
    });
}

#[allow(clippy::modulo_one)]
pub fn get_next_arena() -> *mut Arena {
    init_arenas();
    &mut (ARENAS.write()[INIT_ITERATOR.fetch_sub(1, Ordering::SeqCst) % NUM_ARENAS]) as *mut Arena
}

#[allow(clippy::modulo_one)]
pub fn get_arena_mut(key: u32) -> *mut Arena {
    init_arenas();
    &mut (ARENAS.write()[key as usize % NUM_ARENAS]) as *mut Arena
}

pub struct ArenaInner {
    pub(crate) compression_cache: AtomicMemoryPointer,
    pub(crate) compression_iterator: i16,
    pub(crate) sliding_window: [CompressionSlidingWindow; SLIDING_WINDOW_SIZE],
    pub(crate) superbins: [Superbin; SUPERBIN_ARRAY_MAXSIZE],
}

impl ArenaInner {
    pub(crate) fn initialize_superbin(&mut self, index: usize) {
        self.superbins[index].initialize(index as u16);
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
        (0..SUPERBIN_ARRAY_MAXSIZE).for_each(|i| self.teardown_superblock(i as u16));
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
    pub spinlock: spin::Mutex<ArenaInner>,
}

impl Default for Arena {
    fn default() -> Self {
        let mut superbins: [Superbin; SUPERBIN_ARRAY_MAXSIZE] = from_fn(|_| Superbin::new());
        for (i, superbin) in superbins.iter_mut().enumerate() {
            superbin.initialize(i as u16);
        }

        Arena {
            spinlock: Mutex::new(ArenaInner {
                compression_cache: AtomicMemoryPointer::new(),
                compression_iterator: 1,
                sliding_window: [CompressionSlidingWindow::default(); SLIDING_WINDOW_SIZE],
                superbins,
            }),
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
