use bitfield_struct::bitfield;

use crate::memorymanager::components::superbin::Superbin;
use crate::memorymanager::internals::allocator::{auto_allocate_memory, auto_free_memory, AllocatedBy};
use crate::memorymanager::internals::compression::CompressionState;
use crate::memorymanager::internals::simd_common::{all_bits_set_4096, apply_simd, count_set_bits, get_index_first_set_bit_4096_2};
use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
use crate::memorymanager::pointer::extended_hyperion_pointer::ExtendedHyperionPointer;
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;

pub(crate) const BINOFFSET_BITS: u8 = 12;
pub(crate) const BIN_ELEMENTS: usize = 1 << BINOFFSET_BITS; // 4096
pub(crate) const FREELIST_ELEMENT_BITS: usize = 32;
pub(crate) const BIN_FREELIST_ELEMENTS: usize = BIN_ELEMENTS / FREELIST_ELEMENT_BITS; // 128
pub(crate) const BIN_ELEMENTS_DEFLATED: usize = 256;

#[bitfield(u8)]
pub(crate) struct BinHeader {
    #[bits(2)]
    pub(crate) compression_state: CompressionState,

    #[bits(1)]
    pub(crate) allocated_by: AllocatedBy,

    #[bits(1)]
    pub(crate) chance2nd_read: u8,

    #[bits(1)]
    pub(crate) chance2nd_alloc: u8,

    #[bits(3)]
    __: u8
}

#[derive(Clone)]
#[repr(C, align(1))]
pub(crate) struct Bin {
    pub(crate) header: BinHeader,
    pub(crate) chunks: AtomicMemoryPointer,
    pub(crate) chunk_usage_mask: [u32; BIN_FREELIST_ELEMENTS] // 128 * 32 Bit -> jedes Bit ein Chunk
}

impl Default for Bin {
    fn default() -> Self {
        Bin {
            header: BinHeader::new()
                .with_compression_state(CompressionState::NONE)
                .with_allocated_by(AllocatedBy::Mmap)
                .with_chance2nd_read(0)
                .with_chance2nd_alloc(0),
            chunks: AtomicMemoryPointer::new(),
            chunk_usage_mask: [0; BIN_FREELIST_ELEMENTS]
        }
    }
}

impl Bin {
    /// Sets the compression state, allocation, second read/write flags in the instances header.
    pub(crate) fn set_flags(&mut self, csstate: CompressionState, alloced_by: u8, chance2nd_read: u8, chance2nd_alloc: u8) {
        self.header.set_compression_state(csstate);
        self.header.set_allocated_by(AllocatedBy::from_bits(alloced_by));
        self.header.set_chance2nd_read(chance2nd_read);
        self.header.set_chance2nd_alloc(chance2nd_alloc);
    }

    pub(crate) unsafe fn get_extended_pointer(&mut self, hyperion_pointer: *mut HyperionPointer) -> *mut ExtendedHyperionPointer {
        let offset: usize = (*hyperion_pointer).chunk_id() as usize * size_of::<ExtendedHyperionPointer>();
        self.chunks.get().add(offset) as *mut ExtendedHyperionPointer
    }

    pub(crate) fn get_extended_pointer_to_bin_ref(&mut self, hyperion_pointer: &mut HyperionPointer) -> &mut ExtendedHyperionPointer {
        let offset: usize = hyperion_pointer.chunk_id() as usize * size_of::<ExtendedHyperionPointer>();
        unsafe { (self.chunks.get().add(offset) as *mut ExtendedHyperionPointer).as_mut().unwrap() }
    }

    pub(crate) fn toggle_chunk_usage(&mut self, chunk_id: usize) -> usize {
        let index: usize = chunk_id / FREELIST_ELEMENT_BITS;
        let bit: u32 = 1u32 << (chunk_id % FREELIST_ELEMENT_BITS);
        self.chunk_usage_mask[index] ^= bit;
        index
    }

    /// Checks, if chunks are allocated for the bin instance.
    ///
    /// Returns `true`, if there are no chunks registered for the bin instance.
    /// Returns `false`, otherwise.
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_null()
    }

    /// Checks, if all chunks are unused.
    ///
    /// Returns `true` if all chunks are unused.
    /// Return `false`, otherwise.
    pub(crate) fn check_is_unused(&mut self) -> bool {
        if self.header.chance2nd_alloc() != 1 {
            return false;
        }
        let free_chunks = apply_simd(&self.chunk_usage_mask, count_set_bits);
        free_chunks == BIN_ELEMENTS as i32
    }

    /// Tears down this bin, if all chunks are unused.
    ///
    /// Returns `true`, if the teardown was successful.
    /// Returns `false`, if this bin could not be deleted due to chunks being
    /// used.
    pub(crate) fn teardown_if_unused(&mut self, size: usize) -> bool {
        if self.check_is_unused() {
            self.teardown(size);
            return true;
        }
        false
    }

    /// Checks and returns if all chunks are used and the bin is occupied.
    ///
    /// Returns `true` if all chunks are used.
    /// Returns `false` if there are free chunks available.
    pub(crate) fn is_fully_occupied(&self) -> bool {
        !apply_simd(&self.chunk_usage_mask, all_bits_set_4096)
        // match apply_simd(&self.chunk_usage_mask, all_bits_set_4096) {
        // true => false,
        // false => true,
        // }
    }

    /// Checks if any chunk is free in the bin.
    ///
    /// Returns `Some(index)` containing the id of the found free chunk.
    /// Returns `None`, if all chunks are occupied.
    pub(crate) fn new_chunk_allocation_space_available(&self) -> Option<u8> {
        apply_simd(&self.chunk_usage_mask, get_index_first_set_bit_4096_2).map(|index: i32| index as u8)
    }

    /// Initializes the Bin-Instance with default values. Copies optional cached bin data from the given `Superbin`.
    ///
    /// Sets the Compression State to None and initializes all header fields to 0, all chunks are set to zero,
    /// and the chunk_usage_mask is reset. If cached data exists in the superbin, it is copied and the
    /// cache in the superbin is reset. If there is no cached data, a new memory area is allocated
    /// for the chunks and the allocation type in the header is updated.
    pub(crate) fn initialize(&mut self, superbin: &mut Superbin) {
        self.set_flags(CompressionState::NONE, AllocatedBy::Mmap as u8, 0, 0);
        self.chunks = AtomicMemoryPointer::new();
        self.chunk_usage_mask.fill(u32::MAX);

        if superbin.has_cached_bin() {
            self.chunks.clone_from(&superbin.bin_cache);
            superbin.clear_cache();
        } else {
            let allocated_by: AllocatedBy = unsafe { auto_allocate_memory(&mut self.chunks, superbin.header.size_of_bin() as usize * BIN_ELEMENTS) };
            self.header.set_allocated_by(allocated_by);
        }
    }

    /// Allocates one single chunk within the bin instance. Updates the given `HyperionPointer` to point
    /// to the newly allocated chunk.
    ///
    /// Returns `true`, if the allocation was successful.
    /// Returns `false`, otherwise.
    pub(crate) fn allocate_chunk_unchained(&mut self, hyperion_pointer: &mut HyperionPointer) -> bool {
        self.new_chunk_allocation_space_available()
            .map(|candidate| {
                self.toggle_chunk_usage(candidate as usize);
                hyperion_pointer.set_chunk_id(candidate as u16);
                self.header.set_chance2nd_alloc(0);
                true
            })
            .unwrap_or(false)
    }

    /// Allocates 8 consecutive stored chunks.Updates the given `HyperionPointer` to point
    /// to the newly allocated chunks.
    ///
    /// Returns `true`, if the allocation was successful.
    /// Returns `false`, otherwise.
    pub(crate) fn allocate_consecutive_chunks(&mut self, hyperion_pointer: &mut HyperionPointer) -> bool {
        // Check for 8 free consecutive chunks
        // 8 consecutive chunks are free, if their byte representation in the usage mask is == 255
        for i in 0..(BIN_ELEMENTS / 8) {
            let byte = unsafe { self.chunk_usage_mask.as_mut_ptr().add(i) as *mut u8 };
            if unsafe { *byte == 255 } {
                unsafe { *byte = 0 };
                hyperion_pointer.set_chunk_id(i as u16 * 8);
                self.header.set_chance2nd_alloc(0);
                return true;
            }
        }
        false
    }

    pub(crate) fn teardown(&mut self, size: usize) {
        if self.is_empty() {
            return;
        }
        let bin_size: usize = size
            * match self.header.compression_state() {
                CompressionState::DEFLATE => BIN_ELEMENTS_DEFLATED,
                _ => BIN_ELEMENTS
            };

        if size != size_of::<ExtendedHyperionPointer>() {
            unsafe {
                assert!(auto_free_memory(self.chunks.get(), bin_size, self.header.allocated_by()));
            }
        } else {
            unsafe {
                let mut iterator: *mut ExtendedHyperionPointer = self.chunks.get() as *mut ExtendedHyperionPointer;

                for _ in 0..BIN_ELEMENTS {
                    if (*iterator).has_data() {
                        assert!(auto_free_memory((*iterator).data.get(), (*iterator).alloc_size(), (*iterator).header.alloced_by()));
                    }
                    iterator = iterator.add(1);
                }
                assert!(auto_free_memory(self.chunks.get(), size * BIN_ELEMENTS, self.header.allocated_by()));
            }
        }
    }
}
