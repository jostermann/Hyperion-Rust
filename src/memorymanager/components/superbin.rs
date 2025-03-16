use bitfield_struct::bitfield;

use crate::memorymanager::components::bin::Bin;
use crate::memorymanager::components::metabin::{Metabin, META_MAXMETABINS, META_RINGSIZE_EXT};
use crate::memorymanager::internals::allocator::AllocatedBy;
use crate::memorymanager::internals::simd_common::apply_sorted_insert;
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use crate::memorymanager::pointer::pointer_array::PointerArray;

pub(crate) const INCREMENT_SIZE: usize = 32;
pub(crate) const SUPERBLOCK_INDEX_SIZE_BIT: u8 = 6;
pub(crate) const SUPERBLOCK_ARRAY_MAXSIZE: usize = 1 << SUPERBLOCK_INDEX_SIZE_BIT;

#[bitfield(u64)]
pub(crate) struct SuperbinHeader {
    #[bits(6)]
    pub(crate) superbin_id: u8,

    #[bits(16)]
    pub(crate) size_of_bin: u16,

    #[bits(14)]
    pub(crate) metabins_initialized: u16,

    #[bits(14)]
    pub(crate) metabins_compression_iterator_id: u16,

    #[bits(14)]
    __: u16
}

#[derive(Clone)]
#[repr(C, align(64))]
pub(crate) struct Superbin {
    pub(crate) header: SuperbinHeader,
    pub(crate) bin_cache: AtomicMemoryPointer,
    pub(crate) metabins: PointerArray,
    pub(crate) metabin_ring: [u16; META_RINGSIZE_EXT]
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
            metabin_ring: [0; META_RINGSIZE_EXT]
        }
    }
}

impl Superbin {
    pub(crate) fn new() -> Self {
        Superbin::default()
    }

    pub(crate) fn has_cached_bin(&mut self) -> bool {
        !self.bin_cache.get().is_null()
    }

    pub(crate) fn get_datablock_size(&self) -> u16 {
        match self.header.superbin_id() {
            0 => size_of::<ExtendedHyperionPointer>() as u16,
            _ => self.header.superbin_id() as u16 * INCREMENT_SIZE as u16
        }
    }

    pub(crate) fn clear_cache(&mut self) {
        self.bin_cache = AtomicMemoryPointer::new();
    }

    pub(crate) fn initialize(&mut self, index: u16) {
        self.header.set_superbin_id(index as u8);
        self.header.set_size_of_bin(self.get_datablock_size());
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

    pub(crate) fn teardown_bin(&mut self, bin: &mut Bin) -> bool {
        if bin.is_fully_occupied() {
            return false;
        }

        if !self.has_cached_bin() && bin.header.allocated_by() == AllocatedBy::Mmap {
            self.bin_cache.clone_from(&bin.chunks);
            bin.chunks = AtomicMemoryPointer::new();
        } else {
            bin.teardown(self.get_datablock_size() as usize);
        }
        true
    }

    pub(crate) fn get_metabin(&mut self, hyperion_pointer: &HyperionPointer) -> Option<&Metabin> {
        self.metabins.get(hyperion_pointer.metabin_id() as usize)
    }

    pub(crate) fn get_metabin_candidate(&mut self) -> Option<&mut Metabin> {
        self.metabins.get_mut(self.metabin_ring[0] as usize)
    }

    pub(crate) fn delete_unused_metabins(&mut self) {
        while self.header.metabins_initialized() > 1 {
            let next_metabin_id: u16 = self.header.metabins_initialized();
            let deletion_successful = self.metabins.delete_metabin(next_metabin_id as usize);

            if !deletion_successful {
                return;
            }

            for i in 0..META_RINGSIZE_EXT {
                if self.metabin_ring[i] == next_metabin_id {
                    self.metabin_ring[i] -= 1;
                }
            }

            self.header.set_metabins_initialized(self.header.metabins_initialized() - 1);
        }
    }

    fn shift_metabin_ring_right(&mut self, source_index: usize) {
        self.metabin_ring.copy_within(source_index..META_RINGSIZE_EXT - 1, source_index + 1);
    }

    fn shift_metabin_ring_left(&mut self) {
        self.metabin_ring.copy_within(1..META_RINGSIZE_EXT, 0);
    }

    pub(crate) fn inject_metabin_into_metaring(&mut self, metabin: &Metabin) {
        if metabin.id > 0 {
            match apply_sorted_insert(metabin.id, &self.metabin_ring) {
                Some(index) if index == 0 || (self.metabin_ring[index - 1] != metabin.id) => {
                    self.shift_metabin_ring_right(index);
                    self.metabin_ring[index] = metabin.id;
                },
                _ => {}
            }
        } else if self.metabin_ring[0] != 0 {
            self.shift_metabin_ring_right(0);
            self.metabin_ring[0] = 0;
        }
    }

    pub(crate) fn self_update_metaring(&mut self) {
        let metabins_initialized = self.header.metabins_initialized();

        if self.metabin_ring[0] == metabins_initialized - 1 {
            if metabins_initialized >= META_MAXMETABINS as u16 {
                return;
            }

            let _ = self.metabins.check_extend_pointer_array(metabins_initialized as usize);
            let allocation_successful: bool = self.metabins.new_metabin_at(metabins_initialized as usize);

            if allocation_successful {
                self.metabins.get_mut(metabins_initialized as usize).unwrap().initialize(metabins_initialized);
                self.metabin_ring[0] = metabins_initialized;
                self.header.set_metabins_initialized(metabins_initialized + 1);
            }
        } else {
            self.shift_metabin_ring_left();
            self.metabin_ring[META_RINGSIZE_EXT - 1] = self.header.metabins_initialized();
        }
    }
}

pub(crate) fn get_superbin_id(size: u32) -> u8 {
    (size > 0 && size <= (63 * INCREMENT_SIZE) as u32)
        .then(|| (((size - 1) / INCREMENT_SIZE as u32) + 1) as u8)
        .unwrap_or(0)
}

#[cfg(test)]
mod superbin_test {
    #[test]
    fn test_superbin() {
        assert_eq!(1, 1);
    }
}
