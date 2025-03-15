use crate::memorymanager::components::bin::{Bin, BINOFFSET_BITS, FREELIST_ELEMENT_BITS};
use crate::memorymanager::components::superbin::{Superbin, SUPERBLOCK_INDEX_SIZE_BIT};
use crate::memorymanager::internals::compression::CompressionState;
use crate::memorymanager::internals::simd_common::{apply_simd, get_index_first_set_bit_256_2};
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
use std::array::from_fn;

pub(crate) const METABIN_BITS: u8 = 32 - (BINOFFSET_BITS + SUPERBLOCK_INDEX_SIZE_BIT);
pub(crate) const METABIN_ELEMENTS: usize = 256;
// pub(crate) const METABIN_POINTER_INCREMENT: usize = 16;
pub(crate) const META_RINGSIZE_EXT: usize = 16;
pub(crate) const METABIN_FREELIST_ELEMENTS: usize = 8;
pub(crate) const META_MAXMETABINS: u32 = 1 << METABIN_BITS;

#[derive(Clone)]
#[repr(C)]
pub(crate) struct Metabin {
    pub(crate) free_chunks: u8,
    pub(crate) bin_compression_rr: u8,
    pub(crate) id: u16,
    pub(crate) bin_usage_mask: [u32; METABIN_FREELIST_ELEMENTS],
    pub(crate) bins: [Bin; METABIN_ELEMENTS]
}

impl Default for Metabin {
    fn default() -> Metabin {
        let bins: [Bin; METABIN_ELEMENTS] = from_fn(|_| Bin::default());
        Metabin {
            bin_compression_rr: 0,
            id: 0,
            bin_usage_mask: [0; METABIN_FREELIST_ELEMENTS],
            bins,
            free_chunks: 0
        }
    }
}

impl Metabin {
    pub(crate) fn free_bins(&self) -> usize {
        todo!()
    }

    /// Checks if any bin is free in the metabin.
    ///
    /// Returns `Some(index)` containing the id of the found free bin.
    /// Returns `None` otherwise.
    pub(crate) fn new_bin_allocation_space_available(&self) -> Option<u8> {
        apply_simd(&self.bin_usage_mask, get_index_first_set_bit_256_2).map(|index: i32| index as u8)
        // unsafe { get_index_first_set_bit_256_2(self.bin_usage_mask.as_ptr() as *const c_void) }.map(|index| index as u8)
    }

    /// Initializes the metabin instance with default values.
    ///
    /// Sets the instance's id to the given id and resets the usage_mask.
    pub(crate) fn initialize(&mut self, id: u16) {
        self.id = id;
        self.free_chunks = 255;
        self.bin_usage_mask.fill(u32::MAX);
    }

    pub(crate) fn teardown(&mut self, size: usize) {
        self.bins.iter_mut().for_each(|bin| bin.teardown(size));
        /*for i in 0..METABIN_ELEMENTS {
            self.bins[i].teardown(size);
        }*/
    }

    pub(crate) fn set_bin_as_unused(&mut self, bin_id: usize, chunk_id: usize) {
        let index: usize = bin_id / FREELIST_ELEMENT_BITS;
        let bit: u32 = 1u32 << (chunk_id % FREELIST_ELEMENT_BITS);
        self.bin_usage_mask[index] |= bit;
    }

    /// Marks the Bin stored in hyperion_pointer as occupied
    pub(crate) fn lock_bin(&mut self, hyperion_pointer: &HyperionPointer) -> (usize, usize, u32) {
        let bin_id: usize = hyperion_pointer.bin_id() as usize;
        let index: usize = bin_id / 32;
        let bit: u32 = 1 << (bin_id % FREELIST_ELEMENT_BITS);
        self.bin_usage_mask[index] ^= bit;
        (bin_id, index, bit)
    }

    pub(crate) fn allocate_bin(&mut self, hyperion_pointer: &mut HyperionPointer, superbin: &mut Superbin, chain_count: i32) -> bool {
        // Check whether the given metabin still has room for a new bin
        // Abort the bin allocation, if no space is available
        let optional_candidate: Option<u8> = self.new_bin_allocation_space_available();
        if optional_candidate.is_none() {
            return false;
        }
        let candidate: u8 = optional_candidate.unwrap();

        hyperion_pointer.set_bin_id(candidate);
        let bin: &mut Bin = &mut self.bins[hyperion_pointer.bin_id() as usize];

        if bin.is_empty() {
            bin.initialize(superbin)
        }

        if bin.header.compression_state() != CompressionState::DEFLATE {
            if chain_count == 0 {
                let ret: bool = bin.allocate_chunk_unchained(hyperion_pointer);
                if ret {
                    return true;
                }
            } else {
                let allocation_successful: bool = bin.allocate_consecutive_chunks(hyperion_pointer);
                if allocation_successful {
                    return true;
                }

                // 8 free consecutive chunks not found
                // temporarily disable the current bin and search recursively in the next bin
                // return the found bin and enable the previously disabled bin
                let (_, index, bit) = self.lock_bin(hyperion_pointer);
                let ret = self.allocate_bin(hyperion_pointer, superbin, chain_count);
                self.bin_usage_mask[index] ^= bit;
                return ret;
            }
        }

        let _ = self.lock_bin(hyperion_pointer);
        self.allocate_bin(hyperion_pointer, superbin, chain_count)
    }

    pub(crate) unsafe fn get_bin(&mut self, hyperion_pointer: *mut HyperionPointer) -> *mut Bin {
        &mut self.bins[(*hyperion_pointer).bin_id() as usize] as *mut Bin
    }

    pub(crate) fn get_bin_ref(&mut self, hyperion_pointer: &mut HyperionPointer) -> &mut Bin {
        &mut self.bins[hyperion_pointer.bin_id() as usize]
    }
}
