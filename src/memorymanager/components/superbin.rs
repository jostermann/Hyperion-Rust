use bitfield_struct::bitfield;

use crate::memorymanager::components::bin::Bin;
use crate::memorymanager::components::metabin::{Metabin, METABIN_RING_SIZE, META_MAXMETABINS};
use crate::memorymanager::internals::allocator::AllocatedBy;
use crate::memorymanager::internals::simd_common::apply_sorted_insert;
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use crate::memorymanager::pointer::pointer_array::PointerArray;

/// Default increment size among all superbins. Each superbin `i` is `32 * i` bytes large.
pub(crate) const INCREMENT_SIZE: usize = 32;
/// Maximum amount of superbin entries in the arena (measured in bits).
pub(crate) const SUPERBIN_INDEX_SIZE_BIT: u8 = 6;
/// Maximum amount of superbin entries in the arena.
pub(crate) const SUPERBIN_ARRAY_MAXSIZE: usize = 1 << SUPERBIN_INDEX_SIZE_BIT;
pub(crate) const METABIN_POINTER_INCREMENT: u16 = 16;

/// Stores all metadate of a superbin instance.
#[bitfield(u64)]
pub(crate) struct SuperbinHeader {
    /// This superbin's id.
    #[bits(6)]
    pub(crate) superbin_id: u8,

    /// This superbin's bin-size (`id * 32`).
    #[bits(16)]
    pub(crate) size_of_bin: u16,

    /// The number of metabins currently initialized.
    #[bits(14)]
    pub(crate) metabins_initialized: u16,

    #[bits(14)]
    pub(crate) metabins_compression_iterator_id: u16,

    #[bits(14)]
    __: u16,
}

/// Creates one single superbin instance.
#[derive(Clone)]
#[repr(C, align(64))]
pub(crate) struct Superbin {
    /// Stores all metadata for this superbin.
    pub(crate) header: SuperbinHeader,
    /// Stores a bin cache, that is filled upon deleting a bin. This bin cache can be used to fast-reallocate a bin after deleting it.
    pub(crate) bin_cache: AtomicMemoryPointer,
    /// A pointer to an array of metabins.
    pub(crate) metabins: PointerArray,
    /// A list of 16 non-full metabins that can be used for allocation.
    pub(crate) metabin_ring: [u16; METABIN_RING_SIZE],
}

impl Default for Superbin {
    fn default() -> Self {
        Superbin {
            header: SuperbinHeader::new()
                .with_superbin_id(0)
                .with_size_of_bin(0)
                .with_metabins_initialized(0)
                .with_metabins_compression_iterator_id(0),
            bin_cache: AtomicMemoryPointer::new(),
            metabins: PointerArray::new(1),
            metabin_ring: [0; METABIN_RING_SIZE],
        }
    }
}

impl Superbin {
    pub(crate) fn new() -> Self {
        Superbin::default()
    }

    /// Returns if this superbin instance has some cached bin present.
    pub(crate) fn has_cached_bin(&mut self) -> bool {
        !self.bin_cache.get().is_null()
    }

    /// Returns the size of the superbin's data field.
    /// # Returns
    /// - the size of an [`ExtendedHyperionPointer`], if this superbin's instance id is 0.
    /// - the size of the mmap-region depending on the current id.
    pub(crate) fn get_data_size(&self) -> u16 {
        match self.header.superbin_id() {
            0 => size_of::<ExtendedHyperionPointer>() as u16,
            _ => self.header.superbin_id() as u16 * INCREMENT_SIZE as u16,
        }
    }

    /// Clears the bin cache field.
    /// # Safety
    /// _This function does not free the bin cache._
    pub(crate) fn clear_cache(&mut self) {
        self.bin_cache = AtomicMemoryPointer::new();
    }

    /// Initializes a superbin instance with default values. A single metabin will be created and added to the metabin array.
    pub(crate) fn initialize(&mut self, index: u16) {
        self.header.set_superbin_id(index as u8);
        self.header.set_size_of_bin(self.get_data_size());
        self.header.set_metabins_compression_iterator_id(0);
        self.header.set_metabins_initialized(0);

        if self.metabins.new_metabin_at(0) {
            if let Some(metabin) = self.metabins.get_mut(0) {
                metabin.initialize(0);
                self.metabin_ring[0] = 0;
                self.header.set_metabins_initialized(self.header.metabins_initialized() + 1);
            }
        }
    }

    /// Tears down the specified bin.
    /// # Returns
    /// - `true` if the teardown was successful.
    /// - `false` if the bin is currently in use and cannot be deleted.
    pub(crate) fn teardown_bin(&mut self, bin: &mut Bin) -> bool {
        if bin.is_fully_occupied() {
            return false;
        }

        if !self.has_cached_bin() && bin.header.allocated_by() == AllocatedBy::Mmap {
            self.bin_cache.clone_from(&bin.chunks);
            bin.chunks = AtomicMemoryPointer::new();
        } else {
            bin.teardown(self.get_data_size() as usize);
        }
        true
    }

    /// Returns the metabin from the pointer and this superbin instance.
    pub(crate) fn get_metabin(&mut self, hyperion_pointer: &HyperionPointer) -> Option<&Metabin> {
        self.metabins.get(hyperion_pointer.metabin_id() as usize)
    }

    /// Returns the next non-full metabin instance that can be used for allocation.
    pub(crate) fn get_metabin_candidate(&mut self) -> Option<&mut Metabin> {
        self.metabins.get_mut(self.metabin_ring[0] as usize)
    }

    /// Deletes all unused metabins from this superbin instance.
    pub(crate) fn delete_unused_metabins(&mut self) {
        while self.header.metabins_initialized() > 1 {
            let next_metabin_id: u16 = self.header.metabins_initialized();
            let deletion_successful = self.metabins.delete_metabin(next_metabin_id as usize);

            if !deletion_successful {
                return;
            }

            for i in 0..METABIN_RING_SIZE {
                if self.metabin_ring[i] == next_metabin_id {
                    self.metabin_ring[i] -= 1;
                }
            }

            self.header.set_metabins_initialized(self.header.metabins_initialized() - 1);
        }
    }

    /// Shifts the metabin ring by 1 index right, starting at `source_index`.
    fn shift_metabin_ring_right(&mut self, source_index: usize) {
        self.metabin_ring.copy_within(source_index..METABIN_RING_SIZE - 1, source_index + 1);
    }

    /// Shifts the metabin ring by 1 index left.
    fn shift_metabin_ring_left(&mut self) {
        self.metabin_ring.copy_within(1..METABIN_RING_SIZE, 0);
    }

    /// Adds the specified metabin to the metabin ring. Since the metabin ring is sorted by the metabins id's, this insertion is sorted.
    pub(crate) fn inject_metabin_into_metaring(&mut self, metabin: &Metabin) {
        if metabin.id > 0 {
            match apply_sorted_insert(metabin.id, &self.metabin_ring) {
                Some(index) if index == 0 || (self.metabin_ring[index - 1] != metabin.id) => {
                    self.shift_metabin_ring_right(index);
                    self.metabin_ring[index] = metabin.id;
                },
                _ => {},
            }
        } else if self.metabin_ring[0] != 0 {
            self.shift_metabin_ring_right(0);
            self.metabin_ring[0] = 0;
        }
    }

    /// Self-updates the metabin ring and updates the size of the metabin ring.
    pub(crate) fn self_update_metaring(&mut self) {
        let metabins_initialized = self.header.metabins_initialized();

        if self.metabin_ring[0] == metabins_initialized - 1 {
            if self.header.metabins_initialized() % METABIN_POINTER_INCREMENT == 0 {
                let _ = self.metabins.check_extend_pointer_array(metabins_initialized as usize);
            }
            
            let allocation_successful: bool = self.metabins.new_metabin_at(metabins_initialized as usize);

            if allocation_successful {
                self.metabins.get_mut(metabins_initialized as usize).unwrap().initialize(metabins_initialized);
                self.metabin_ring[0] = metabins_initialized;
                self.header.set_metabins_initialized(metabins_initialized + 1);
            }
        } else {
            self.shift_metabin_ring_left();
            self.metabin_ring[METABIN_RING_SIZE - 1] = self.header.metabins_initialized();
        }
    }
}

/// Returns the superbin id for the specified size.
pub(crate) fn get_superbin_id(size: u32) -> u8 {
    /*(size > 0 && size <= (63 * INCREMENT_SIZE) as u32).then(|| (((size - 1) / INCREMENT_SIZE as u32) + 1) as u8).unwrap_or(0)*/
    if size <= (63 * INCREMENT_SIZE) as u32 {
        (((size - 1) / INCREMENT_SIZE as u32) + 1) as u8
    } else {
        0
    }
}
