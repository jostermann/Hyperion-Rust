//! Provides the core functionalities for Extended Hyperion pointers.
//!
//! Heap allocations are pretty fast, but many reallocations or allocations
//! that fluctuate widely in size result in significant heap fragmentation.
//! To reduce heap fragmentation, smaller allocations are stored in large memory
//! mapped segments, and only large allocations are placed on the heap. This
//! large heap allocations.
//!
//! Extended Bins are stored in Superbin 0 and are smaller (16 Bytes) than the default
//! Bin (up to 521 Bytes). Instead of memory mapped regions as chunk data, Extended Bins
//! store just one `ExtendedHyperionPointer`, containing some household variables
//! and a heap pointer to the stored data.
//!
//! The `ExtendedHeapPointer` can be used to retrieve the data, and to retrieve
//! - the allocated size
//! - the amount of overallocation within the heap allocation
//! - the amount of chained extended bins
//! - the data's compression state

use bitfield_struct::bitfield;

use crate::memorymanager::internals::allocator::{auto_free_memory, AllocatedBy};
use crate::memorymanager::internals::compression::CompressionState;
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;

/// Header type for an `ExtendedHyperionPointer`.
#[bitfield(u8)]
pub struct ExtendedHyperionPointerHeader {
    /// The allocation method used for allocating the data field.
    #[bits(1)]
    pub alloced_by: AllocatedBy,

    /// The compression state of the data pointed to by data.
    #[bits(2)]
    pub compression_state: CompressionState,

    /// TODO
    #[bits(1)]
    pub chance2nd_realloc: u8,

    /// TODO
    #[bits(4)]
    pub chained_pointer_count: u8
}

/// Holds all data used by the `ExtendedHyperionPointer`.
#[repr(align(16))]
pub struct ExtendedHyperionPointer {
    /// Stores a header-instance.
    pub header: ExtendedHyperionPointerHeader,
    /// TODO
    pub chance2nd_read: u8,
    /// Stores an AtomicPointer to the heap, where the data is stored.
    pub data: AtomicMemoryPointer,
    /// Total size originally allocated or reallocated.
    pub requested_size: i32,
    /// Amount of overallocation
    pub overallocated: i16
}

impl ExtendedHyperionPointer {
    /// Returns the total allocation size used by the calling pointer.
    pub fn alloc_size(&self) -> usize {
        (self.requested_size + self.overallocated as i32) as usize
    }

    /// Automatically frees the memory region pointed to by data and deletes
    /// the pointer to this region.
    ///
    /// # Safety
    /// _This operation cannot be undone! Once this operation has finished, the
    /// stored data and the pointer are lost. Use this function only when tearing
    /// down the associated Bin._
    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    /// Checks and returns, if the calling `ExtendedHyperionPointer` has data stored.
    ///
    /// Returns `true` if data ist stored.
    /// Returns `false`, otherwise.
    pub fn has_data(&self) -> bool {
        self.data.is_notnull()
    }

    /// Updates the calling Extended pointer's flags to the given values.
    pub fn set_flags(
        &mut self, requested_size: i32, overallocated: i16, c2r: u8, c2reall: u8, compression_state: CompressionState, chained_pointer: u8
    ) {
        self.requested_size = requested_size;
        self.overallocated = overallocated;
        self.header.set_compression_state(compression_state);
        self.chance2nd_read = c2r;
        self.header.set_chance2nd_realloc(c2reall);
        self.header.set_chained_pointer_count(chained_pointer);
    }
}

#[cfg(test)]
mod extended_hyperion_pointer_tests {
    use crate::memorymanager::api::{AtomicMemoryPointer, ExtendedHyperionPointer};
    use crate::memorymanager::internals::allocator::AllocatedBy::{Heap, Mmap};
    use crate::memorymanager::internals::compression::CompressionState;
    use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointerHeader;

    #[test]
    fn test_fields() {
        let mut ehp: ExtendedHyperionPointer = ExtendedHyperionPointer {
            header: ExtendedHyperionPointerHeader::new()
                .with_alloced_by(Mmap)
                .with_chained_pointer_count(0)
                .with_chance2nd_realloc(0)
                .with_compression_state(CompressionState::NONE),
            chance2nd_read: 0,
            data: AtomicMemoryPointer::new(),
            requested_size: 0,
            overallocated: 0,
        };

        assert_eq!(ehp.requested_size, 0, "Expected requested_size to be 0, but got {}.", ehp.requested_size);
        assert_eq!(ehp.overallocated, 0, "Expected overallocated to be 0, but got {}.", ehp.overallocated);
        assert_eq!(ehp.chance2nd_read, 0, "Expected chance2nd_read to be 0, but got {}.", ehp.chance2nd_read);
        assert_eq!(ehp.header.alloced_by(), Mmap, "Expected alloced_by to be Mmap, but got {:?}.", ehp.header.alloced_by());
        assert_eq!(ehp.header.chained_pointer_count(), 0, "Expected chained_pointer_count to be 0, but got {}.", ehp.header.chained_pointer_count());
        assert_eq!(ehp.header.chance2nd_realloc(), 0, "Expected chance2nd_realloc to be 0, but got {}.", ehp.header.chance2nd_realloc());
        assert_eq!(ehp.header.compression_state(), CompressionState::NONE, "Expected compression_state to be NONE, but got {:?}.", ehp.header.compression_state());

        ehp.requested_size = 50;
        ehp.overallocated = 100;
        ehp.chance2nd_read = 1;
        ehp.header.set_alloced_by(Heap);
        ehp.header.set_chained_pointer_count(12);
        ehp.header.set_chance2nd_realloc(1);
        ehp.header.set_compression_state(CompressionState::LZ4);

        assert_eq!(ehp.requested_size, 50, "Expected requested_size to be 50 after modification, but got {}.", ehp.requested_size);
        assert_eq!(ehp.overallocated, 100, "Expected overallocated to be 100 after modification, but got {}.", ehp.overallocated);
        assert_eq!(ehp.chance2nd_read, 1, "Expected chance2nd_read to be 1 after modification, but got {}.", ehp.chance2nd_read);
        assert_eq!(ehp.header.alloced_by(), Heap, "Expected alloced_by to be Heap after modification, but got {:?}.", ehp.header.alloced_by());
        assert_eq!(ehp.header.chained_pointer_count(), 12, "Expected chained_pointer_count to be 12 after modification, but got {}.", ehp.header.chained_pointer_count());
        assert_eq!(ehp.header.chance2nd_realloc(), 1, "Expected chance2nd_realloc to be 1 after modification, but got {}.", ehp.header.chance2nd_realloc());
        assert_eq!(ehp.header.compression_state(), CompressionState::LZ4, "Expected compression_state to be LZ4 after modification, but got {:?}.", ehp.header.compression_state());
    }

    #[test]
    fn test_alloc_size() {
        let ehp: ExtendedHyperionPointer = ExtendedHyperionPointer {
            header: ExtendedHyperionPointerHeader::new()
                .with_alloced_by(Mmap)
                .with_chained_pointer_count(0)
                .with_chance2nd_realloc(0)
                .with_compression_state(CompressionState::NONE),
            chance2nd_read: 0,
            data: AtomicMemoryPointer::new(),
            requested_size: 50,
            overallocated: 100,
        };
        assert_eq!(ehp.alloc_size(), 150, "Expected alloc_size to be 150, but got {}", ehp.alloc_size());
    }

    #[test]
    fn test_has_data() {
        let ehp: ExtendedHyperionPointer = ExtendedHyperionPointer {
            header: ExtendedHyperionPointerHeader::new()
                .with_alloced_by(Mmap)
                .with_chained_pointer_count(0)
                .with_chance2nd_realloc(0)
                .with_compression_state(CompressionState::NONE),
            chance2nd_read: 0,
            data: AtomicMemoryPointer::new(),
            requested_size: 50,
            overallocated: 100,
        };
        assert!(!ehp.has_data(), "Expected has_data to be false, but got true.");
    }
}
