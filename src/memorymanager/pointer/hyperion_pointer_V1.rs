//! Provides the core functionalities for Hyperion pointers.
//!
//! Heap allocations are pretty fast, but many reallocations or allocations
//! that fluctuate widely in size result in significant heap fragmentation.
//! To reduce heap fragmentation, smaller allocations are stored in large memory
//! mapped segments, and only large allocations are placed on the heap. This
//! module refers to smaller allocations in large `mmap` regions.
//!
//! Each Bin stores 4096 chunks, whereby each chunk is a memory segment in which
//! a container from the trie is stored. The memory manager acting as middleware,
//! decouples the trie from the virtual memory. THis allows for the assignment
//! of containers to chunks to be variable.
//!
//! `HyperionPointer` store the id's of all bin types in the memory hierarchy
//! along the path from the superbin to the chunk. This information can be
//! used to retrieve the containers from the chunks at any time.


use bitfield_struct::bitfield;

/// `HyperionPointer`, defined as bitfield-struct
#[bitfield(u64)]
pub struct HyperionPointer {
    /// 6 bit superbin id, ranging from 0 to 63
    #[bits(6)]
    pub superbin_id: u8,

    /// 14 bit metabin id, ranging from 0 to 16383
    #[bits(14)]
    pub metabin_id: u16,

    /// 8 bit bin id, ranging from 0 to 255
    #[bits(8)]
    pub bin_id: u8,

    /// 12 bit chunk id, ranging from 0 to 4095
    #[bits(12)]
    pub chunk_id: u16,

    #[bits(24)]
    __: u32,
}

impl HyperionPointer {
    /// Returns `true`, if the calling `HyperionPointer` is an `ExtendedHyperionPointer`.
    /// Returns `false`, otherwise.
    pub(crate) fn is_extended_pointer(&self) -> bool {
        self.superbin_id() == 0
    }
}

#[cfg(test)]
mod pointer_tests {
    use crate::memorymanager::pointer::hyperion_pointer::{HyperionPointer};

    #[test]
    fn test_hyperion_pointer_size() {
        let sid: u8 = 5;
        let mid: u16 = 2503;
        let bid: u8 = 197;
        let cid: u16 = 4008;
        let hp: HyperionPointer = HyperionPointer::new()
            .with_superbin_id(sid)
            .with_metabin_id(mid)
            .with_bin_id(bid)
            .with_chunk_id(cid);

        assert_eq!(size_of_val(&hp), 8);
        assert_eq!(hp.superbin_id(), sid);
        assert_eq!(hp.metabin_id(), mid);
        assert_eq!(hp.bin_id(), bid);
        assert_eq!(hp.chunk_id(), cid);
    }
}
