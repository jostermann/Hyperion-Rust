use std::array::from_fn;
use std::ptr::write_bytes;
use crate::memorymanager::components::bin::{Bin, BINOFFSET_BITS, FREELIST_ELEMENT_BITS};
use crate::memorymanager::components::superbin::{Superbin, SUPERBLOCK_INDEX_SIZE_BIT};
use crate::memorymanager::internals::compression::CompressionState;
use crate::memorymanager::internals::simd_common::{apply_simd, get_index_first_set_bit_256_2};
use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;

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
        for i in 0..METABIN_ELEMENTS {
            self.bins[i].teardown(size);
        }
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

#[cfg(test)]
mod metabin_test {
    use std::mem::MaybeUninit;

    use crate::memorymanager::components::bin::{BinHeader, BIN_FREELIST_ELEMENTS};
    use crate::memorymanager::components::metabin::*;
    use crate::memorymanager::components::superbin::{Superbin, SuperbinHeader};
    use crate::memorymanager::internals::allocator::AllocatedBy;
    use crate::memorymanager::pointer::atomic_memory_pointer::AtomicMemoryPointer;
    use crate::memorymanager::pointer::hyperion_pointer::HyperionPointer;
    use crate::memorymanager::pointer::pointer_array::PointerArray;

    #[test]
    fn test_metabin_size() {
        let freelist: [u32; METABIN_FREELIST_ELEMENTS] = [255, 255, 255, 255, 255, 255, 255, 255]; // TODO: u8? Kann nicht größer als 255 werden, da nur 256 Bins pro
        let mut bin_arrays: [Bin; METABIN_ELEMENTS] = unsafe { MaybeUninit::uninit().assume_init() };
        // let _p: [u32; 3] = [1, 2, 3];

        for i in 0..METABIN_ELEMENTS {
            let header: BinHeader = BinHeader::new()
                .with_compression_state(CompressionState::NONE)
                .with_allocated_by(AllocatedBy::Mmap)
                .with_chance2nd_read(0)
                .with_chance2nd_alloc(0);

            // let _data: *mut c_void = p.as_ptr() as *mut c_void;
            let data = AtomicMemoryPointer::new();
            let mut freelist: [u32; BIN_FREELIST_ELEMENTS] = unsafe { MaybeUninit::uninit().assume_init() };
            for j in 0..BIN_FREELIST_ELEMENTS {
                freelist[j] = 255;
            }
            let bin: Bin = Bin {
                header,
                chunks: AtomicMemoryPointer::new(),
                chunk_usage_mask: freelist
            };
            bin_arrays[i] = bin;
        }

        let mut m_bin: Metabin = Metabin {
            bin_usage_mask: freelist,
            bins: bin_arrays,
            id: 2,
            free_chunks: 10,
            bin_compression_rr: 0
        };

        let mut hyp: HyperionPointer = HyperionPointer::new().with_superbin_id(0).with_metabin_id(0).with_bin_id(0).with_chunk_id(0);

        let mut sup: Superbin = Superbin {
            metabin_ring: [0; META_RINGSIZE_EXT],
            metabins: PointerArray::new(2),
            bin_cache: AtomicMemoryPointer::new(),
            header: SuperbinHeader::new()
                .with_size_of_bin(200)
                .with_metabins_initialized(0)
                .with_superbin_id(1)
                .with_metabins_compression_iterator_id(0)
        };

        let size = size_of_val(&m_bin.bins[0].chunks);
        println!("{size}");

        m_bin.allocate_bin(&mut hyp, &mut sup, 0);
        let bin = &mut (m_bin.bins[0]);
        // teardown_bin(bin, 528);
        assert_eq!(1, 1);
    }
}
